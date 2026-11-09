from __future__ import annotations

import json
import logging
import shutil
import subprocess
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from prguard.models import Confidence, Severity

log = logging.getLogger(__name__)

SEVERITIES = {
    "ERROR": Severity.HIGH,
    "WARNING": Severity.MEDIUM,
    "INFO": Severity.LOW,
    # newer semgrep versions use these names
    "CRITICAL": Severity.CRITICAL,
    "HIGH": Severity.HIGH,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
}


class SemgrepError(RuntimeError):
    pass


@dataclass(frozen=True)
class SemgrepResult:
    rule_id: str
    path: str
    start_line: int
    end_line: int
    severity: Severity
    confidence: Confidence
    message: str

    def touches(self, first: int, last: int) -> bool:
        return self.start_line <= last and self.end_line >= first


@dataclass
class SemgrepRun:
    results: list[SemgrepResult] = field(default_factory=list)
    # paths semgrep couldn't parse, e.g. a suggested fix that broke the syntax
    failed_paths: set[str] = field(default_factory=set)

    def for_path(self, path: str) -> list[SemgrepResult]:
        return [r for r in self.results if r.path == path]


def parse_output(data: dict[str, Any]) -> SemgrepRun:
    run = SemgrepRun()
    for raw in data.get("results") or []:
        extra = raw.get("extra", {})
        metadata = extra.get("metadata", {}) or {}
        try:
            confidence = Confidence.parse(str(metadata.get("confidence", "MEDIUM")))
        except KeyError:
            confidence = Confidence.MEDIUM
        run.results.append(
            SemgrepResult(
                rule_id=raw["check_id"],
                path=raw["path"],
                start_line=raw["start"]["line"],
                end_line=raw["end"]["line"],
                severity=SEVERITIES.get(str(extra.get("severity", "")).upper(), Severity.MEDIUM),
                confidence=confidence,
                message=str(extra.get("message", "")).strip(),
            )
        )
    for error in data.get("errors") or []:
        path = error.get("path") or (error.get("spans") or [{}])[0].get("file")
        # the type is a plain string in older versions and ["PartialParsing", [...]] in newer ones
        kind = str(error.get("type", ""))
        if path and any(word in kind for word in ("Syntax", "PartialParsing", "ParseError")):
            run.failed_paths.add(path)
    return run


class Semgrep:
    def __init__(self, configs: Sequence[str], timeout: int = 300, binary: str = "semgrep") -> None:
        self.configs = list(configs)
        self.timeout = timeout
        self.binary = binary

    @staticmethod
    def available(binary: str = "semgrep") -> bool:
        return shutil.which(binary) is not None

    def scan(self, root: Path, targets: Sequence[Path]) -> SemgrepRun:
        if not targets:
            return SemgrepRun()
        cmd = [self.binary, "scan", "--json", "--quiet", "--metrics=off", "--disable-version-check"]
        for config in self.configs:
            cmd += ["--config", config]
        cmd += [str(t) for t in targets]

        log.debug("running %s", " ".join(cmd))
        # S603: the command is built from our own config, never from PR content
        proc = subprocess.run(  # noqa: S603
            cmd, cwd=root, capture_output=True, text=True, timeout=self.timeout, check=False
        )
        # 0 = clean, 1 = findings; anything else means semgrep itself failed
        if proc.returncode not in (0, 1):
            raise SemgrepError(f"semgrep exited with {proc.returncode}: {proc.stderr.strip()[-500:]}")
        try:
            return parse_output(json.loads(proc.stdout))
        except (json.JSONDecodeError, KeyError) as e:
            raise SemgrepError(f"couldn't read semgrep output: {e}") from e
