from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path

import pytest

from prguard.diff import FileDiff, parse_patch
from prguard.llm import LLMReview
from prguard.models import Finding
from prguard.semgrep import Semgrep, SemgrepResult, SemgrepRun

FIXTURES = Path(__file__).parent / "fixtures"

needs_semgrep = pytest.mark.skipif(not Semgrep.available(), reason="semgrep isn't installed")


def new_file(path: str, lines: Sequence[str]) -> FileDiff:
    patch = f"@@ -0,0 +1,{len(lines)} @@\n" + "\n".join("+" + line for line in lines)
    return parse_patch(path, "added", patch)


class FakeReviewer:
    def __init__(self, findings: Sequence[Finding] = (), summary: str = "", error: Exception | None = None):
        self.findings = list(findings)
        self.summary = summary
        self.error = error
        self.prompts: list[str] = []

    def review(self, prompt: str) -> LLMReview:
        self.prompts.append(prompt)
        if self.error:
            raise self.error
        return LLMReview(self.summary, list(self.findings))


class FakeScanner:
    """Pretends to be semgrep: flags any line containing one of the given needles."""

    def __init__(self, needles: dict[str, str] | None = None):
        self.needles = needles or {}
        self.scans: list[list[Path]] = []

    def scan(self, root: Path, targets: Sequence[Path]) -> SemgrepRun:
        self.scans.append(list(targets))
        run = SemgrepRun()
        for target in targets:
            for number, line in enumerate((root / target).read_text().splitlines(), start=1):
                for needle, rule in self.needles.items():
                    if needle in line:
                        run.results.append(
                            SemgrepResult(
                                rule, target.as_posix(), number, number, *_defaults(), f"found {needle}"
                            )
                        )
        return run


def _defaults():  # type: ignore[no-untyped-def]
    from prguard.models import Confidence, Severity

    return Severity.HIGH, Confidence.HIGH


class DictContent:
    def __init__(self, files: dict[str, str]):
        self.files = files

    def get(self, path: str) -> str | None:
        return self.files.get(path)
