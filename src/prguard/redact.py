"""Strips secrets out of diffs before anything is sent to the model.

This deliberately over-redacts. A false positive costs the model a little context; a
false negative sends someone's production key to a third party.
"""

from __future__ import annotations

import math
import re
from collections import Counter
from dataclasses import dataclass, replace

from prguard.diff import FileDiff
from prguard.paths import matches_any

PRIVATE_KEY_BEGIN = re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY( BLOCK)?-----")
PRIVATE_KEY_END = re.compile(r"-----END [A-Z0-9 ]*PRIVATE KEY( BLOCK)?-----")

# Well known token formats. Order matters: anthropic keys also look like openai keys.
TOKEN_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("aws-access-key-id", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("github-token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,255}\b")),
    ("github-token", re.compile(r"\bgithub_pat_[A-Za-z0-9_]{22,255}\b")),
    ("anthropic-api-key", re.compile(r"\bsk-ant-[A-Za-z0-9_-]{20,}")),
    ("openai-api-key", re.compile(r"\bsk-(?:proj-|svcacct-)?[A-Za-z0-9_-]{20,}")),
    ("stripe-key", re.compile(r"\b[rs]k_(?:live|test)_[A-Za-z0-9]{16,}\b")),
    ("slack-token", re.compile(r"\bxox[abposr]-[A-Za-z0-9-]{10,}")),
    ("google-api-key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}")),
]

URL_CREDENTIALS = re.compile(r"(?P<prefix>\b[a-z][a-z0-9+.-]*://[^\s:/@]+:)(?P<password>[^\s@/]+)@", re.I)

SENSITIVE_WORDS = "password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key|private[_-]?key|credential"
SENSITIVE_NAME = rf"[\w.-]*(?:{SENSITIVE_WORDS})[\w.-]*"
# password = "...", "api_key": '...', SECRET_TOKEN: "..."
SECRET_ASSIGNMENT = re.compile(
    rf"""(?P<lhs>{SENSITIVE_NAME}["']?\s*(?::|=|:=|=>)\s*)(?P<quote>["'])(?P<value>[^"'\s]{{6,}})(?P=quote)""",
    re.I,
)

BASE64ISH = re.compile(r"[A-Za-z0-9+/=_-]{24,}")
HEXISH = re.compile(r"\b[0-9a-fA-F]{32,}\b")

PLACEHOLDER_HINTS = (
    "example",
    "changeme",
    "change_me",
    "placeholder",
    "dummy",
    "your",
    "xxx",
    "***",
    "redacted",
)

# never sent to the model at all
SENSITIVE_FILES = [
    "**/.env",
    "**/.env.*",
    "**/*.pem",
    "**/*.key",
    "**/*.p12",
    "**/*.pfx",
    "**/*.jks",
    "**/*.keystore",
    "**/id_rsa*",
    "**/id_ecdsa*",
    "**/id_ed25519*",
    "**/.npmrc",
    "**/.pypirc",
    "**/credentials.json",
]
SAFE_ENV_FILES = ["**/.env.example", "**/.env.sample", "**/.env.template"]


@dataclass(frozen=True)
class Redaction:
    path: str
    line: int | None  # new-file line number, None if the line was removed
    kind: str
    # high-entropy blobs get redacted but they're often just hashes, so don't report them
    reportable: bool = True


def is_sensitive_file(path: str) -> bool:
    return matches_any(path, SENSITIVE_FILES) and not matches_any(path, SAFE_ENV_FILES)


def shannon_entropy(value: str) -> float:
    counts = Counter(value)
    return -sum(n / len(value) * math.log2(n / len(value)) for n in counts.values())


def looks_like_placeholder(value: str) -> bool:
    lowered = value.lower()
    if lowered[0] in "$<{%" or len(set(lowered)) == 1:
        return True
    return any(hint in lowered for hint in PLACEHOLDER_HINTS)


def _char_class(c: str) -> int:
    return 0 if c.isupper() else 1 if c.islower() else 2 if c.isdigit() else 3


def _looks_random(candidate: str) -> bool:
    if shannon_entropy(candidate) < 3.5:
        return False
    # Random strings flip between upper, lower and digits all the time, identifiers like
    # handlesLargeInputs2 or snake_case_names barely do. Entropy alone can't tell them apart.
    chars = candidate.replace("_", "").replace("-", "")
    switches = sum(_char_class(a) != _char_class(b) for a, b in zip(chars, chars[1:], strict=False))
    return switches / len(chars) >= 0.3


def redact_text(text: str) -> tuple[str, list[tuple[str, bool]]]:
    """Returns the redacted text and the (kind, reportable) of everything that was removed."""
    found: list[tuple[str, bool]] = []

    for kind, pattern in TOKEN_PATTERNS:
        text, n = pattern.subn(f"[REDACTED:{kind}]", text)
        found.extend([(kind, True)] * n)

    text, n = URL_CREDENTIALS.subn(r"\g<prefix>[REDACTED:url-password]@", text)
    found.extend([("url-password", True)] * n)

    def assignment(match: re.Match[str]) -> str:
        if looks_like_placeholder(match["value"]):
            return match[0]
        found.append(("hardcoded-credential", True))
        return f"{match['lhs']}{match['quote']}[REDACTED:hardcoded-credential]{match['quote']}"

    text = SECRET_ASSIGNMENT.sub(assignment, text)

    def blob(match: re.Match[str]) -> str:
        if not _looks_random(match[0]):
            return match[0]
        found.append(("high-entropy-string", False))
        return "[REDACTED:high-entropy-string]"

    text = BASE64ISH.sub(blob, text)

    def hex_blob(match: re.Match[str]) -> str:
        value = match[0]
        if not (any(c.isdigit() for c in value) and any(c.isalpha() for c in value)):
            return value
        found.append(("hex-string", False))
        return "[REDACTED:hex-string]"

    text = HEXISH.sub(hex_blob, text)
    return text, found


def redact_file(diff: FileDiff) -> tuple[FileDiff, list[Redaction]]:
    redactions: list[Redaction] = []
    lines = []
    in_private_key = False

    for line in diff.lines:
        if line.kind == "@":
            lines.append(line)
            continue

        if in_private_key or PRIVATE_KEY_BEGIN.search(line.text):
            if not in_private_key:
                redactions.append(Redaction(diff.path, line.new_lineno, "private-key"))
            in_private_key = not PRIVATE_KEY_END.search(line.text)
            lines.append(replace(line, text="[REDACTED:private-key]"))
            continue

        text, found = redact_text(line.text)
        redactions.extend(
            Redaction(diff.path, line.new_lineno, kind, reportable) for kind, reportable in found
        )
        lines.append(replace(line, text=text))

    return replace(diff, lines=lines), redactions
