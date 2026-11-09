from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from prguard.models import Confidence, Severity

DEFAULT_IGNORE = [
    "**/*.lock",
    "**/package-lock.json",
    "**/pnpm-lock.yaml",
    "**/go.sum",
    "**/*.min.js",
    "**/*.map",
    "**/*.svg",
    "**/*.png",
    "**/*.jpg",
    "**/*.gif",
    "**/vendor/**",
    "**/node_modules/**",
    "**/dist/**",
]

DEFAULT_TEST_PATTERNS = [
    "**/tests/**",
    "**/test/**",
    "**/__tests__/**",
    "**/test_*.py",
    "**/*_test.py",
    "**/*_test.go",
    "**/*.test.[jt]s",
    "**/*.test.[jt]sx",
    "**/*.spec.[jt]s",
    "**/*Test.java",
    "**/*IT.java",
    "**/*Tests.cs",
]

SOURCE_EXTENSIONS = {
    ".py",
    ".js",
    ".jsx",
    ".ts",
    ".tsx",
    ".go",
    ".java",
    ".kt",
    ".rb",
    ".php",
    ".cs",
    ".rs",
    ".c",
    ".cpp",
}

EFFORTS = ("low", "medium", "high", "xhigh", "max")


class ConfigError(ValueError):
    pass


@dataclass
class Settings:
    model: str = "claude-opus-5-5"
    effort: str = "high"
    # fail the check if anything at or above this severity is found ("none" never fails)
    fail_on: Severity | None = None
    min_severity: Severity = Severity.LOW
    min_confidence: Confidence = Confidence.MEDIUM
    max_files: int = 50
    max_file_chars: int = 20_000
    max_total_chars: int = 150_000
    ignore: list[str] = field(default_factory=lambda: list(DEFAULT_IGNORE))
    test_patterns: list[str] = field(default_factory=lambda: list(DEFAULT_TEST_PATTERNS))
    semgrep_enabled: bool = True
    semgrep_configs: list[str] = field(default_factory=lambda: ["p/default"])

    def validate(self) -> None:
        if self.effort not in EFFORTS:
            raise ConfigError(f"effort must be one of {', '.join(EFFORTS)}, got {self.effort!r}")
        for name in ("max_files", "max_file_chars", "max_total_chars"):
            if getattr(self, name) <= 0:
                raise ConfigError(f"{name} must be positive")


def _severity_or_none(value: str) -> Severity | None:
    if value.strip().lower() in ("", "none", "never", "off"):
        return None
    return Severity.parse(value)


def _apply(settings: Settings, raw: Mapping[str, Any]) -> None:
    try:
        if "model" in raw:
            settings.model = str(raw["model"])
        if "effort" in raw:
            settings.effort = str(raw["effort"]).lower()
        if "fail_on" in raw:
            settings.fail_on = _severity_or_none(str(raw["fail_on"]))
        if "min_severity" in raw:
            settings.min_severity = Severity.parse(str(raw["min_severity"]))
        if "min_confidence" in raw:
            settings.min_confidence = Confidence.parse(str(raw["min_confidence"]))
        for name in ("max_files", "max_file_chars", "max_total_chars"):
            if name in raw:
                setattr(settings, name, int(raw[name]))
    except KeyError as e:
        raise ConfigError(f"unknown value {e}") from e
    except (TypeError, ValueError) as e:
        raise ConfigError(str(e)) from e

    # user ignores are added to the defaults rather than replacing them
    settings.ignore += [str(p) for p in raw.get("ignore", []) or []]
    if "test_patterns" in raw:
        settings.test_patterns = [str(p) for p in raw["test_patterns"]]

    semgrep = raw.get("semgrep") or {}
    if "enabled" in semgrep:
        settings.semgrep_enabled = bool(semgrep["enabled"])
    if "configs" in semgrep:
        settings.semgrep_configs = [str(c) for c in semgrep["configs"]]


# action inputs come through as PRGUARD_* env vars and win over the config file
ENV_OVERRIDES = {
    "PRGUARD_MODEL": "model",
    "PRGUARD_EFFORT": "effort",
    "PRGUARD_FAIL_ON": "fail_on",
    "PRGUARD_MIN_SEVERITY": "min_severity",
}


def parse_settings(text: str | None, env: Mapping[str, str] = os.environ, source: str = "config") -> Settings:
    settings = Settings()
    if text:
        raw = yaml.safe_load(text) or {}
        if not isinstance(raw, dict):
            raise ConfigError(f"{source} should contain a mapping")
        _apply(settings, raw)

    overrides = {key: env[var] for var, key in ENV_OVERRIDES.items() if env.get(var, "").strip()}
    _apply(settings, overrides)
    settings.validate()
    return settings


def load_settings(path: Path | None, env: Mapping[str, str] = os.environ) -> Settings:
    text = path.read_text() if path is not None and path.is_file() else None
    return parse_settings(text, env, source=str(path))
