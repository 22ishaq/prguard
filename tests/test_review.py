from conftest import DictContent, FakeReviewer, FakeScanner, new_file

from prguard.config import Settings
from prguard.diff import parse_patch
from prguard.llm import ReviewFailed
from prguard.models import Confidence, Finding, Severity
from prguard.review import run_review

# fake secrets are split up so GitHub's own secret scanning leaves this file alone
AWS_KEY = "AKIA" + "Z5FAKEKEY1234567"
GH_TOKEN = "ghp_" + "Zx9" * 12

APP = ["import subprocess", "", "def run(cmd):", "    return subprocess.run(cmd, shell=True)", ""]


def llm_finding(path: str = "app.py", line: int = 4, **overrides: object) -> Finding:
    values: dict[str, object] = {
        "path": path,
        "line": line,
        "category": "security",
        "severity": Severity.HIGH,
        "confidence": Confidence.HIGH,
        "title": "Shell injection",
        "explanation": "cmd comes from the request",
    }
    values.update(overrides)
    return Finding(**values)  # type: ignore[arg-type]


def review(files, contents=None, reviewer=None, scanner=None, **settings):  # type: ignore[no-untyped-def]
    return run_review(files, DictContent(contents or {}), Settings(**settings), reviewer, scanner)


def test_secrets_never_reach_the_model() -> None:
    config = new_file(
        "settings.py", [f'AWS_ACCESS_KEY_ID = "{AWS_KEY}"', f"GITHUB_TOKEN = '{GH_TOKEN}'", "DEBUG = True"]
    )
    reviewer = FakeReviewer()

    result = review([config], reviewer=reviewer)

    (prompt,) = reviewer.prompts
    assert AWS_KEY not in prompt
    assert GH_TOKEN not in prompt
    assert "[REDACTED:aws-access-key-id]" in prompt
    assert "DEBUG = True" in prompt
    assert result.redactions == 2
    assert [(f.line, f.title, f.source) for f in result.findings] == [
        (1, "Hardcoded secret (aws-access-key-id)", "secrets"),
        (2, "Hardcoded secret (github-token)", "secrets"),
    ]


def test_credential_files_are_flagged_but_not_sent() -> None:
    env = new_file(".env", ["DB_PASSWORD=hunter2hunter2", "PORT=8000"])
    reviewer = FakeReviewer()

    result = review([env, new_file("app.py", APP)], reviewer=reviewer)

    assert "hunter2" not in reviewer.prompts[0]
    assert ".env" not in reviewer.prompts[0]
    assert result.skipped == [(".env", "looks like a credentials file, so it was never sent to the model")]
    assert [f.title for f in result.findings] == ["Credentials file committed"]


def test_findings_outside_the_diff_are_dropped() -> None:
    patch = "@@ -1,3 +1,4 @@\n import subprocess\n+import shlex\n \n def run(cmd):"
    diff = parse_patch("app.py", "modified", patch)
    reviewer = FakeReviewer(
        [
            llm_finding(line=2, title="added line"),
            llm_finding(line=3, title="context line"),
            llm_finding(line=40, title="not in the diff"),
            llm_finding(path="elsewhere.py", line=1, title="other file"),
        ]
    )

    result = review([diff], reviewer=reviewer)

    assert sorted(f.title for f in result.findings) == ["added line", "context line"]


def test_range_spanning_a_gap_collapses_to_one_line() -> None:
    patch = "@@ -1,2 +1,2 @@\n a\n+b\n@@ -10,2 +10,2 @@\n x\n+y"
    diff = parse_patch("app.py", "modified", patch)
    reviewer = FakeReviewer([llm_finding(line=11, start_line=2, suggestion="z")])

    (finding,) = review([diff], reviewer=reviewer).findings

    assert finding.start_line is None
    assert finding.suggestion is None


def test_suggestions_containing_redaction_markers_are_removed() -> None:
    reviewer = FakeReviewer([llm_finding(suggestion="    key = '[REDACTED:github-token]'")])

    (finding,) = review([new_file("app.py", APP)], reviewer=reviewer).findings

    assert finding.suggestion is None


def test_suggestions_are_checked_with_semgrep() -> None:
    reviewer = FakeReviewer(
        [
            llm_finding(suggestion="    return subprocess.run(cmd, shell=True, check=True)"),
            llm_finding(line=1, title="Second", suggestion="import subprocess  # nosec"),
        ]
    )
    scanner = FakeScanner({"shell=True": "shell-true"})

    result = review([new_file("app.py", APP)], {"app.py": "\n".join(APP)}, reviewer, scanner)

    by_title = {f.title: f for f in result.findings}
    assert by_title["Shell injection"].suggestion is None
    assert "shell-true" in (by_title["Shell injection"].suggestion_dropped or "")
    assert by_title["Second"].suggestion == "import subprocess  # nosec"


def test_semgrep_confirms_llm_findings_and_adds_its_own() -> None:
    lines = APP + ["eval(input())"]
    reviewer = FakeReviewer([llm_finding(line=4)])
    scanner = FakeScanner({"shell=True": "shell-true", "eval(": "no-eval"})

    result = review([new_file("app.py", lines)], {"app.py": "\n".join(lines)}, reviewer, scanner)

    llm, semgrep = sorted(result.findings, key=lambda f: f.line)
    assert (llm.source, llm.confirmed_by) == ("llm", ["shell-true"])
    assert (semgrep.source, semgrep.line, semgrep.title) == ("semgrep", 6, "No eval")
    assert "[no-eval]" in reviewer.prompts[0]


def test_semgrep_results_on_untouched_lines_are_ignored() -> None:
    patch = "@@ -1,2 +1,3 @@\n eval(x)\n+y = 1\n z = 2"
    diff = parse_patch("app.py", "modified", patch)
    scanner = FakeScanner({"eval(": "no-eval"})

    result = review([diff], {"app.py": "eval(x)\ny = 1\nz = 2\n"}, scanner=scanner)

    assert result.findings == []


def test_low_confidence_needs_semgrep_backing() -> None:
    reviewer = FakeReviewer(
        [
            llm_finding(line=1, title="hunch", confidence=Confidence.LOW),
            llm_finding(line=4, title="backed hunch", confidence=Confidence.LOW),
        ]
    )
    scanner = FakeScanner({"shell=True": "shell-true"})

    result = review([new_file("app.py", APP)], {"app.py": "\n".join(APP)}, reviewer, scanner)

    assert [f.title for f in result.findings] == ["backed hunch"]


def test_min_severity_filters() -> None:
    reviewer = FakeReviewer([llm_finding(severity=Severity.LOW)])

    assert review([new_file("app.py", APP)], reviewer=reviewer, min_severity=Severity.MEDIUM).findings == []


def test_flags_source_changes_without_tests() -> None:
    result = review([new_file("app.py", APP), new_file("README.md", ["hi"])])

    assert result.untested == ["app.py"]


def test_changed_tests_clear_the_missing_tests_note() -> None:
    result = review([new_file("app.py", APP), new_file("tests/test_app.py", ["def test_run(): ..."])])

    assert result.untested == []
    assert result.test_files == ["tests/test_app.py"]


def test_size_limits_skip_files_and_say_so() -> None:
    big = new_file("big.py", ["x = 1"] * 500)
    reviewer = FakeReviewer()

    result = review(
        [new_file("app.py", APP), big, new_file("yarn.lock", ["a"])], reviewer=reviewer, max_file_chars=1000
    )

    assert "big.py" not in reviewer.prompts[0]
    assert dict(result.skipped) == {
        "big.py": "diff is bigger than max_file_chars (1000)",
        "yarn.lock": "ignored by config",
    }


def test_llm_failure_still_returns_other_findings() -> None:
    config = new_file("settings.py", [f'KEY = "{AWS_KEY}"'])
    reviewer = FakeReviewer(error=ReviewFailed("the model declined to review this diff"))

    result = review([config], reviewer=reviewer)

    assert result.llm_error == "the model declined to review this diff"
    assert [f.source for f in result.findings] == ["secrets"]


def test_most_severe_first() -> None:
    reviewer = FakeReviewer(
        [
            llm_finding(line=1, title="low", severity=Severity.LOW),
            llm_finding(line=3, title="critical", severity=Severity.CRITICAL),
            llm_finding(line=2, title="medium", severity=Severity.MEDIUM),
        ]
    )

    result = review([new_file("app.py", APP)], reviewer=reviewer)

    assert [f.title for f in result.findings] == ["critical", "medium", "low"]
