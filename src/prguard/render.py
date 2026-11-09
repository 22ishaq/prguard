"""Markdown for review comments, the review summary and the job summary."""

from __future__ import annotations

import re
from collections import Counter
from collections.abc import Iterable, Sequence

from prguard.models import Finding, Severity
from prguard.review import ReviewResult

MARKER = "<!-- prguard:{} -->"
MARKER_RE = re.compile(r"<!-- prguard:([0-9a-f]{16}) -->")


def _fence(code: str) -> str:
    # a suggestion that itself contains ``` needs a longer fence
    longest = max((len(m) for m in re.findall(r"`+", code)), default=0)
    return "`" * max(3, longest + 1)


def comment_body(f: Finding) -> str:
    parts = [f"**{f.severity.label().capitalize()} · {f.category}: {f.title}**", "", f.explanation]
    if f.suggestion:
        fence = _fence(f.suggestion)
        parts += ["", f"{fence}suggestion", f.suggestion.rstrip("\n"), fence]
    if f.suggestion_dropped:
        parts += ["", f"_There was a suggested fix, but it was left out because {f.suggestion_dropped}._"]

    meta = [f"from {f.source}", f"confidence {f.confidence.name.lower()}"]
    if f.confirmed_by and f.source != "semgrep":
        meta.append("also flagged by " + ", ".join(f"`{rule}`" for rule in f.confirmed_by))
    parts += ["", f"<sub>PRGuard · {' · '.join(meta)}</sub>", MARKER.format(f.fingerprint())]
    return "\n".join(parts)


def review_comment(f: Finding) -> dict[str, object]:
    comment: dict[str, object] = {"path": f.path, "line": f.line, "side": "RIGHT", "body": comment_body(f)}
    if f.start_line is not None:
        comment["start_line"] = f.start_line
        comment["start_side"] = "RIGHT"
    return comment


def posted_fingerprints(bodies: Iterable[str]) -> set[str]:
    found: set[str] = set()
    for body in bodies:
        found.update(MARKER_RE.findall(body or ""))
    return found


def _counts(findings: Sequence[Finding]) -> str:
    counts = Counter(f.severity for f in findings)
    return ", ".join(f"{counts[s]} {s.label()}" for s in sorted(counts, reverse=True)) or "nothing"


def notes(result: ReviewResult) -> list[str]:
    out = []
    if result.untested:
        files = ", ".join(f"`{p}`" for p in result.untested[:10])
        more = f" and {len(result.untested) - 10} more" if len(result.untested) > 10 else ""
        out.append(f"Source files changed but no tests did: {files}{more}.")
    if result.redactions:
        out.append(
            f"{result.redactions} possible secret(s) were redacted before the diff was sent to the model."
        )
    if result.llm_error:
        out.append(f"The LLM review didn't run: {result.llm_error}. Only the Semgrep and secret checks ran.")
    if result.semgrep_error:
        out.append(f"Semgrep failed: {result.semgrep_error}")
    if result.skipped:
        out.append("Not reviewed:\n" + "\n".join(f"  - `{path}`: {why}" for path, why in result.skipped))
    return out


def summary_body(result: ReviewResult, new: Sequence[Finding]) -> str:
    parts = [f"### PRGuard found {_counts(result.findings)}"]
    if len(new) != len(result.findings):
        parts.append(f"{len(new)} of these are new since the last review.")
    if result.summary:
        parts += ["", result.summary]
    extra = notes(result)
    if extra:
        parts += [""] + [f"- {n}" for n in extra]
    return "\n".join(parts)


def findings_list(findings: Sequence[Finding]) -> str:
    """Used when GitHub won't take inline comments, so everything goes in the review body."""
    return "\n".join(
        f"- **{f.severity.label()}** `{f.path}:{f.line}` {f.title}: {f.explanation}" for f in findings
    )


def step_summary(result: ReviewResult) -> str:
    parts = [f"## PRGuard: {_counts(result.findings)}", ""]
    if result.findings:
        parts += ["| Severity | Location | Finding | Source |", "|---|---|---|---|"]
        for f in result.findings:
            title = f.title.replace("|", "\\|")
            parts.append(f"| {f.severity.label()} | `{f.path}:{f.line}` | {title} | {f.source} |")
        parts.append("")
    parts += [f"- {n}" for n in notes(result)]
    return "\n".join(parts) + "\n"


def text_report(result: ReviewResult) -> str:
    lines = []
    for f in result.findings:
        lines.append(f"{f.path}:{f.line}: [{f.severity.label()}/{f.category}] {f.title} ({f.source})")
        lines.append(f"    {f.explanation}")
        if f.suggestion:
            lines.append("    suggested fix:")
            lines += [f"      {s}" for s in f.suggestion.splitlines()]
    lines += notes(result)
    lines.append(f"{len(result.findings)} finding(s): {_counts(result.findings)}")
    return "\n".join(lines)


def worst(findings: Sequence[Finding]) -> Severity | None:
    return max((f.severity for f in findings), default=None)
