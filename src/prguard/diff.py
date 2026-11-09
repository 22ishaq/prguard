"""Parsing unified diffs into something we can map findings onto.

GitHub's pull request files API gives us one ``patch`` per file (just the hunks, no
``diff --git`` header). Local mode reads a whole ``git diff`` instead, which gets split
into the same per-file shape.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

HUNK_HEADER = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")


@dataclass
class DiffLine:
    kind: str  # "+", "-", " " or "@" for hunk headers
    text: str
    new_lineno: int | None


@dataclass
class FileDiff:
    path: str
    status: str  # added, modified, removed, renamed
    lines: list[DiffLine] = field(default_factory=list)

    @property
    def added(self) -> dict[int, str]:
        return {ln.new_lineno: ln.text for ln in self.lines if ln.kind == "+" and ln.new_lineno is not None}

    @property
    def commentable(self) -> set[int]:
        """Lines on the new side of the diff that GitHub lets us attach a review comment to."""
        return {ln.new_lineno for ln in self.lines if ln.kind in "+ " and ln.new_lineno is not None}

    @property
    def size(self) -> int:
        return sum(len(ln.text) + 1 for ln in self.lines)

    def render(self) -> str:
        """The diff with new-file line numbers in the gutter, which is what the model sees."""
        out = [f"--- {self.path} ({self.status})"]
        for ln in self.lines:
            if ln.kind == "@":
                out.append(ln.text)
            else:
                number = "" if ln.new_lineno is None else str(ln.new_lineno)
                out.append(f"{number:>5} {ln.kind} {ln.text}")
        return "\n".join(out)


def parse_patch(path: str, status: str, patch: str | None) -> FileDiff:
    diff = FileDiff(path=path, status=status)
    if not patch:
        return diff

    new_lineno = 0
    for raw in patch.splitlines():
        header = HUNK_HEADER.match(raw)
        if header:
            new_lineno = int(header.group(3))
            diff.lines.append(DiffLine("@", raw, None))
            continue
        if raw.startswith("\\"):
            # "\ No newline at end of file"
            continue
        kind, text = (raw[0], raw[1:]) if raw else (" ", "")
        if kind == "+":
            diff.lines.append(DiffLine("+", text, new_lineno))
            new_lineno += 1
        elif kind == "-":
            diff.lines.append(DiffLine("-", text, None))
        else:
            diff.lines.append(DiffLine(" ", text, new_lineno))
            new_lineno += 1
    return diff


def parse_git_diff(text: str) -> list[FileDiff]:
    """Split the output of ``git diff`` into per-file diffs."""
    files: list[FileDiff] = []
    path: str | None = None
    status = "modified"
    hunks: list[str] = []
    in_hunks = False

    def flush() -> None:
        if path is not None:
            files.append(parse_patch(path, status, "\n".join(hunks)))

    for line in text.splitlines():
        if line.startswith("diff --git "):
            flush()
            # "diff --git a/foo b/foo" - the b/ side is the new path
            path = line.split(" b/", 1)[1] if " b/" in line else None
            status, hunks, in_hunks = "modified", [], False
        elif not in_hunks and line.startswith("new file mode"):
            status = "added"
        elif not in_hunks and line.startswith("deleted file mode"):
            status = "removed"
        elif not in_hunks and line.startswith("rename to "):
            status = "renamed"
            path = line[len("rename to ") :]
        elif not in_hunks and line.startswith("+++ "):
            target = line[4:]
            if target.startswith("b/"):
                path = target[2:]
        elif line.startswith("@@"):
            in_hunks = True
            hunks.append(line)
        elif in_hunks:
            hunks.append(line)
    flush()
    return files
