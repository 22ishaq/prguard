"""Checks suggested fixes with Semgrep before anyone sees them.

A suggestion is applied to a copy of the file and the copy is scanned. If the patched
lines don't parse, or Semgrep still has something to say about them, the suggestion is
dropped and the comment goes out without it.
"""

from __future__ import annotations

import ast
import tempfile
from collections.abc import Mapping, Sequence
from dataclasses import replace
from pathlib import Path
from typing import Protocol

from prguard.models import Finding
from prguard.semgrep import SemgrepError, SemgrepRun


class Scanner(Protocol):
    def scan(self, root: Path, targets: Sequence[Path]) -> SemgrepRun: ...


def apply_suggestion(content: str, first: int, last: int, replacement: str) -> str:
    """Replaces lines first..last (1-based, inclusive) with the replacement text."""
    lines = content.splitlines(keepends=True)
    new_lines = [line + "\n" for line in replacement.splitlines()]
    patched = lines[: first - 1] + new_lines + lines[last:]
    # don't add a trailing newline the file didn't have
    if last >= len(lines) and lines and not lines[-1].endswith("\n") and patched:
        patched[-1] = patched[-1].removesuffix("\n")
    return "".join(patched)


def _parses(path: str, content: str) -> bool:
    """Semgrep's parsers quietly recover from some syntax errors, so Python fixes also
    get a real compile check. Other languages rely on Semgrep reporting parse errors."""
    if not path.endswith(".py"):
        return True
    try:
        ast.parse(content)
    except SyntaxError:
        return False
    return True


def _drop(finding: Finding, reason: str) -> Finding:
    return replace(finding, suggestion=None, suggestion_dropped=reason)


def verify_suggestions(
    findings: Sequence[Finding], sources: Mapping[str, str], scanner: Scanner | None
) -> list[Finding]:
    pending = {i: f for i, f in enumerate(findings) if f.suggestion}
    if not pending:
        return list(findings)
    if scanner is None:
        # we never show a fix we couldn't check
        return [
            _drop(f, "Semgrep wasn't available to check it") if i in pending else f
            for i, f in enumerate(findings)
        ]

    targets: dict[int, str] = {}
    unparseable: set[int] = set()
    run: SemgrepRun | None = SemgrepRun()
    with tempfile.TemporaryDirectory(prefix="prguard-suggestions-") as tmp:
        root = Path(tmp)
        for i, finding in pending.items():
            original = sources.get(finding.path)
            if original is None:
                continue
            assert finding.suggestion is not None
            patched = apply_suggestion(original, finding.first_line, finding.line, finding.suggestion)
            if not _parses(finding.path, patched):
                unparseable.add(i)
                continue
            rel = Path(f"s{i}") / finding.path
            (root / rel).parent.mkdir(parents=True, exist_ok=True)
            (root / rel).write_text(patched)
            targets[i] = rel.as_posix()

        if targets:
            try:
                run = scanner.scan(root, [Path(t) for t in targets.values()])
            except SemgrepError:
                run = None

    checked = []
    for i, finding in enumerate(findings):
        if i not in pending:
            checked.append(finding)
        elif i in unparseable:
            checked.append(_drop(finding, "the patched file didn't parse"))
        elif i not in targets:
            checked.append(_drop(finding, "the file's contents couldn't be loaded to check it"))
        elif run is None:
            checked.append(_drop(finding, "Semgrep failed while checking it"))
        else:
            checked.append(_check(finding, targets[i], run))
    return checked


def _check(finding: Finding, path: str, run: SemgrepRun) -> Finding:
    assert finding.suggestion is not None
    last = finding.first_line + max(len(finding.suggestion.splitlines()), 1) - 1
    hits = [r for r in run.for_path(path) if r.touches(finding.first_line, last)]
    if path in run.failed_paths:
        return _drop(finding, "the patched file didn't parse")
    if hits:
        rules = ", ".join(sorted({f"`{r.rule_id}`" for r in hits}))
        return _drop(finding, f"Semgrep still flagged the patched code ({rules})")
    return finding
