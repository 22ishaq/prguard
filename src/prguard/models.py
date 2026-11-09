from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from enum import IntEnum


class Severity(IntEnum):
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @classmethod
    def parse(cls, value: str) -> Severity:
        return cls[value.strip().upper()]

    def label(self) -> str:
        return self.name.lower()


class Confidence(IntEnum):
    LOW = 1
    MEDIUM = 2
    HIGH = 3

    @classmethod
    def parse(cls, value: str) -> Confidence:
        return cls[value.strip().upper()]


SECURITY = "security"
MISSING_TESTS = "missing-tests"
CATEGORIES = (SECURITY, MISSING_TESTS)


@dataclass
class Finding:
    path: str
    line: int
    category: str
    severity: Severity
    confidence: Confidence
    title: str
    explanation: str
    start_line: int | None = None
    suggestion: str | None = None
    # where it came from: "llm", "semgrep" or "secrets"
    source: str = "llm"
    # semgrep rules that flagged the same line
    confirmed_by: list[str] = field(default_factory=list)
    # set when we had a suggested fix but threw it away
    suggestion_dropped: str | None = None

    @property
    def first_line(self) -> int:
        return self.start_line if self.start_line is not None else self.line

    def fingerprint(self) -> str:
        """Identifies a finding across pushes so we don't post the same comment twice.

        Line numbers move around as people push more commits, so they're left out.
        """
        raw = f"{self.path}\0{self.category}\0{self.title.strip().lower()}"
        return hashlib.sha256(raw.encode()).hexdigest()[:16]
