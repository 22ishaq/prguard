"""Glob matching with ``**`` support, which fnmatch doesn't do properly."""

from __future__ import annotations

import re
from collections.abc import Iterable
from functools import lru_cache


@lru_cache(maxsize=256)
def _compile(pattern: str) -> re.Pattern[str]:
    out = []
    i = 0
    while i < len(pattern):
        if pattern.startswith("**/", i):
            out.append("(?:.*/)?")
            i += 3
        elif pattern.startswith("**", i):
            out.append(".*")
            i += 2
        elif pattern[i] == "*":
            out.append("[^/]*")
            i += 1
        elif pattern[i] == "?":
            out.append("[^/]")
            i += 1
        elif pattern[i] == "[" and (end := pattern.find("]", i + 1)) != -1:
            out.append("[" + re.escape(pattern[i + 1 : end]) + "]")
            i = end + 1
        else:
            out.append(re.escape(pattern[i]))
            i += 1
    return re.compile("".join(out) + r"\Z")


def matches(path: str, pattern: str) -> bool:
    return _compile(pattern).match(path) is not None


def matches_any(path: str, patterns: Iterable[str]) -> bool:
    return any(matches(path, p) for p in patterns)
