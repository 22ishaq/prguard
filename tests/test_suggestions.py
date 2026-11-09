from conftest import FIXTURES, FakeScanner, needs_semgrep

from prguard.models import Confidence, Finding, Severity
from prguard.semgrep import Semgrep
from prguard.suggestions import apply_suggestion, verify_suggestions

SOURCE = "import subprocess\n\n\ndef run(cmd):\n    return subprocess.run(cmd, shell=True)\n"


def finding(suggestion: str | None, line: int = 5, start: int | None = None) -> Finding:
    return Finding(
        path="tool.py",
        line=line,
        start_line=start,
        category="security",
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        title="Shell injection",
        explanation="...",
        suggestion=suggestion,
    )


def test_apply_replaces_the_range() -> None:
    assert apply_suggestion("a\nb\nc\nd\n", 2, 3, "B\nC2\nC3") == "a\nB\nC2\nC3\nd\n"


def test_apply_can_delete_lines() -> None:
    assert apply_suggestion("a\nb\nc\n", 2, 2, "") == "a\nc\n"


def test_apply_keeps_missing_trailing_newline() -> None:
    assert apply_suggestion("a\nb", 2, 2, "B") == "a\nB"


def test_keeps_a_fix_semgrep_is_happy_with() -> None:
    scanner = FakeScanner({"shell=True": "shell-true"})

    (checked,) = verify_suggestions([finding("    return subprocess.run(cmd)")], {"tool.py": SOURCE}, scanner)

    assert checked.suggestion == "    return subprocess.run(cmd)"
    assert checked.suggestion_dropped is None


def test_drops_a_fix_that_still_has_the_problem() -> None:
    scanner = FakeScanner({"shell=True": "shell-true"})
    bad = finding("    return subprocess.run(cmd, shell=True, check=True)")

    (checked,) = verify_suggestions([bad], {"tool.py": SOURCE}, scanner)

    assert checked.suggestion is None
    assert "shell-true" in (checked.suggestion_dropped or "")


def test_only_the_replaced_lines_count() -> None:
    # shell=True elsewhere in the file isn't this suggestion's fault
    source = SOURCE + "\n\ndef other(cmd):\n    subprocess.call(cmd, shell=True)\n"
    scanner = FakeScanner({"shell=True": "shell-true"})

    (checked,) = verify_suggestions([finding("    return subprocess.run(cmd)")], {"tool.py": source}, scanner)

    assert checked.suggestion is not None


def test_findings_without_suggestions_are_untouched() -> None:
    plain = finding(None)
    scanner = FakeScanner()

    assert verify_suggestions([plain], {"tool.py": SOURCE}, scanner) == [plain]
    assert scanner.scans == []


def test_unchecked_fixes_are_never_shown() -> None:
    (checked,) = verify_suggestions([finding("    return subprocess.run(cmd)")], {"tool.py": SOURCE}, None)

    assert checked.suggestion is None
    assert checked.suggestion_dropped == "Semgrep wasn't available to check it"


@needs_semgrep
def test_with_real_semgrep() -> None:
    scanner = Semgrep([str(FIXTURES / "rules.yml")])
    good = finding("    return subprocess.run(cmd)")
    still_bad = finding("    return subprocess.run(cmd, shell=True, check=True)")
    broken = finding("    return subprocess.run(cmd,")

    checked = verify_suggestions([good, still_bad, broken], {"tool.py": SOURCE}, scanner)

    assert checked[0].suggestion is not None
    assert checked[1].suggestion is None and "shell-true" in (checked[1].suggestion_dropped or "")
    assert checked[2].suggestion is None and checked[2].suggestion_dropped == "the patched file didn't parse"
