"""The review pipeline: diff in, filtered and verified findings out."""

from __future__ import annotations

import logging
import tempfile
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Protocol

from prguard.config import SOURCE_EXTENSIONS, Settings
from prguard.diff import FileDiff
from prguard.llm import Reviewer, ReviewFailed, build_prompt
from prguard.models import CATEGORIES, SECURITY, Confidence, Finding, Severity
from prguard.paths import matches_any
from prguard.redact import Redaction, is_sensitive_file, redact_file, redact_text
from prguard.semgrep import SemgrepError, SemgrepResult
from prguard.suggestions import Scanner, verify_suggestions

log = logging.getLogger(__name__)

SOURCE_PRIORITY = {"secrets": 0, "llm": 1, "semgrep": 2}


class ContentSource(Protocol):
    def get(self, path: str) -> str | None: ...


@dataclass
class ReviewResult:
    findings: list[Finding] = field(default_factory=list)
    summary: str = ""
    reviewed: list[str] = field(default_factory=list)
    skipped: list[tuple[str, str]] = field(default_factory=list)
    redactions: int = 0
    test_files: list[str] = field(default_factory=list)
    untested: list[str] = field(default_factory=list)
    llm_error: str | None = None
    semgrep_error: str | None = None


def select_files(files: Sequence[FileDiff], settings: Settings, result: ReviewResult) -> list[FileDiff]:
    kept: list[FileDiff] = []
    total = 0
    for f in files:
        reason = None
        if f.status == "removed":
            continue
        if is_sensitive_file(f.path):
            reason = "looks like a credentials file, so it was never sent to the model"
        elif matches_any(f.path, settings.ignore):
            reason = "ignored by config"
        elif not f.lines:
            reason = "no text diff (binary, or too big for GitHub to show)"
        elif len(kept) >= settings.max_files:
            reason = f"over the {settings.max_files} file limit"
        elif f.size > settings.max_file_chars:
            reason = f"diff is bigger than max_file_chars ({settings.max_file_chars})"
        elif total + f.size > settings.max_total_chars:
            reason = f"would go over max_total_chars ({settings.max_total_chars})"

        if reason:
            result.skipped.append((f.path, reason))
        else:
            kept.append(f)
            total += f.size
    return kept


def credentials_file_finding(diff: FileDiff) -> Finding | None:
    lines = sorted(diff.added)
    if diff.status != "added" or not lines:
        return None
    return Finding(
        path=diff.path,
        line=lines[0],
        category=SECURITY,
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        title="Credentials file committed",
        explanation=(
            f"`{PurePosixPath(diff.path).name}` usually holds secrets. Remove it from the branch, add it "
            "to .gitignore and rotate anything that was in it, since it's now in the git history."
        ),
        source="secrets",
    )


def secret_findings(path: str, redactions: Sequence[Redaction], added: Mapping[int, str]) -> list[Finding]:
    findings = []
    for r in redactions:
        if not r.reportable or r.line is None or r.line not in added:
            continue
        findings.append(
            Finding(
                path=path,
                line=r.line,
                category=SECURITY,
                severity=Severity.CRITICAL if r.kind == "private-key" else Severity.HIGH,
                confidence=Confidence.HIGH,
                title=f"Hardcoded secret ({r.kind})",
                explanation=(
                    "This line looks like it contains a real secret. Load it from the environment or a "
                    "secret manager instead, and rotate it: pushing it to a branch already exposed it."
                ),
                source="secrets",
            )
        )
    return findings


def scan_sources(scanner: Scanner, sources: Mapping[str, str]) -> list[SemgrepResult]:
    with tempfile.TemporaryDirectory(prefix="prguard-head-") as tmp:
        root = Path(tmp)
        targets = []
        for path, content in sources.items():
            target = root / path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(content)
            targets.append(Path(path))
        return scanner.scan(root, targets).results


def _range_is_commentable(diff: FileDiff, first: int, last: int) -> bool:
    commentable = diff.commentable
    return all(n in commentable for n in range(first, last + 1))


def validate_llm_findings(findings: Sequence[Finding], files: Mapping[str, FileDiff]) -> list[Finding]:
    """Drops anything GitHub wouldn't let us post, or that points outside the diff."""
    valid = []
    for f in findings:
        diff = files.get(f.path)
        if diff is None or f.category not in CATEGORIES or f.line not in diff.commentable:
            log.info("dropping finding outside the diff: %s:%s %s", f.path, f.line, f.title)
            continue
        if f.start_line is not None and (
            f.start_line > f.line or not _range_is_commentable(diff, f.start_line, f.line)
        ):
            # the range is unusable, so is a suggestion written for it
            f.start_line = None
            f.suggestion = None
        if f.suggestion and "[REDACTED:" in f.suggestion:
            # applying this would write our placeholder into their code
            f.suggestion = None
        valid.append(f)
    return valid


def semgrep_finding(result: SemgrepResult, diff: FileDiff) -> Finding | None:
    commentable = diff.commentable
    lines = [n for n in range(result.start_line, result.end_line + 1) if n in commentable]
    if not lines:
        return None
    first, last = lines[0], lines[-1]
    if not _range_is_commentable(diff, first, last):
        first = last
    return Finding(
        path=result.path,
        line=last,
        start_line=first if first != last else None,
        category=SECURITY,
        severity=result.severity,
        confidence=result.confidence,
        title=result.rule_id.rsplit(".", 1)[-1].replace("-", " ").capitalize(),
        explanation=result.message,
        source="semgrep",
        confirmed_by=[result.rule_id],
    )


def merge(
    findings: list[Finding], semgrep: Sequence[SemgrepResult], files: Mapping[str, FileDiff]
) -> list[Finding]:
    for f in findings:
        f.confirmed_by = sorted(
            {r.rule_id for r in semgrep if r.path == f.path and r.touches(f.first_line, f.line)}
        )

    for result in semgrep:
        covered = any(f.path == result.path and result.touches(f.first_line, f.line) for f in findings)
        diff = files.get(result.path)
        if not covered and diff is not None:
            extra = semgrep_finding(result, diff)
            if extra:
                findings.append(extra)

    # one finding per line and category; prefer secrets, then the model, then raw semgrep
    best: dict[tuple[str, int, str], Finding] = {}
    for f in findings:
        key = (f.path, f.line, f.category)
        if key not in best or SOURCE_PRIORITY[f.source] < SOURCE_PRIORITY[best[key].source]:
            best[key] = f
    return list(best.values())


def run_review(
    files: Sequence[FileDiff],
    contents: ContentSource,
    settings: Settings,
    reviewer: Reviewer | None,
    scanner: Scanner | None,
    title: str = "",
) -> ReviewResult:
    result = ReviewResult()
    findings: list[Finding] = []

    result.test_files = [f.path for f in files if matches_any(f.path, settings.test_patterns)]
    kept = select_files(files, settings, result)
    for f in files:
        if is_sensitive_file(f.path) and (creds := credentials_file_finding(f)):
            findings.append(creds)

    redacted = []
    for f in kept:
        clean, redactions = redact_file(f)
        redacted.append(clean)
        result.redactions += len(redactions)
        findings += secret_findings(f.path, redactions, f.added)
    result.reviewed = [f.path for f in kept]
    by_path = {f.path: f for f in kept}

    if not result.test_files:
        result.untested = [
            f.path for f in kept if PurePosixPath(f.path).suffix in SOURCE_EXTENSIONS and len(f.added) > 0
        ]

    sources = {f.path: content for f in kept if (content := contents.get(f.path)) is not None}

    semgrep_results: list[SemgrepResult] = []
    if scanner is not None and sources:
        try:
            semgrep_results = [
                r
                for r in scan_sources(scanner, sources)
                if r.path in by_path and any(r.touches(n, n) for n in by_path[r.path].added)
            ]
        except SemgrepError as e:
            log.warning("semgrep failed: %s", e)
            result.semgrep_error = str(e)

    if reviewer is not None and redacted:
        # semgrep messages can quote matched code, so they get the same treatment as the diff
        hints = [
            SemgrepResult(
                r.rule_id,
                r.path,
                r.start_line,
                r.end_line,
                r.severity,
                r.confidence,
                redact_text(r.message)[0],
            )
            for r in semgrep_results
        ]
        prompt = build_prompt(redacted, hints, result.test_files, title)
        try:
            review = reviewer.review(prompt)
        except ReviewFailed as e:
            log.warning("LLM review failed: %s", e)
            result.llm_error = str(e)
        else:
            result.summary = review.summary
            findings += validate_llm_findings(review.findings, by_path)

    findings = merge(findings, semgrep_results, by_path)
    findings = verify_suggestions(findings, sources, scanner)
    findings = [
        f
        for f in findings
        if f.severity >= settings.min_severity and (f.confidence >= settings.min_confidence or f.confirmed_by)
    ]
    findings.sort(key=lambda f: (-f.severity, f.path, f.line))
    result.findings = findings
    return result
