from pathlib import Path

import pytest
from conftest import FIXTURES, needs_semgrep

from prguard.models import Confidence, Severity
from prguard.semgrep import Semgrep, SemgrepError, parse_output

SAMPLE = {
    "results": [
        {
            "check_id": "python.lang.security.audit.eval-detected.eval-detected",
            "path": "app/views.py",
            "start": {"line": 12, "col": 5},
            "end": {"line": 13, "col": 1},
            "extra": {"message": "Detected eval()", "severity": "WARNING", "metadata": {"confidence": "LOW"}},
        },
        {
            "check_id": "custom.rule",
            "path": "app/db.py",
            "start": {"line": 3, "col": 1},
            "end": {"line": 3, "col": 9},
            "extra": {"message": "raw sql", "severity": "ERROR"},
        },
    ],
    "errors": [
        {"type": ["PartialParsing", []], "path": "app/broken.py", "message": "Syntax error at line 2"},
        {"type": "Timeout", "path": "app/slow.py", "message": "took too long"},
    ],
}


def test_parses_results() -> None:
    run = parse_output(SAMPLE)

    first, second = run.results
    assert first.rule_id.endswith("eval-detected")
    assert (first.start_line, first.end_line) == (12, 13)
    assert first.severity is Severity.MEDIUM
    assert first.confidence is Confidence.LOW
    assert second.severity is Severity.HIGH
    assert second.confidence is Confidence.MEDIUM


def test_only_parse_failures_count_as_failed_paths() -> None:
    assert parse_output(SAMPLE).failed_paths == {"app/broken.py"}


def test_touches_is_inclusive() -> None:
    result = parse_output(SAMPLE).results[0]

    assert result.touches(13, 20)
    assert result.touches(1, 12)
    assert not result.touches(14, 20)


@needs_semgrep
def test_runs_real_semgrep(tmp_path: Path) -> None:
    (tmp_path / "pkg").mkdir()
    (tmp_path / "pkg" / "app.py").write_text("import os\nvalue = eval(os.environ['X'])\n")

    run = Semgrep([str(FIXTURES / "rules.yml")]).scan(tmp_path, [Path("pkg/app.py")])

    assert [(r.rule_id.rsplit(".", 1)[-1], r.path, r.start_line) for r in run.results] == [
        ("no-eval", "pkg/app.py", 2)
    ]


@needs_semgrep
def test_bad_config_raises(tmp_path: Path) -> None:
    (tmp_path / "a.py").write_text("x = 1\n")

    with pytest.raises(SemgrepError):
        Semgrep([str(tmp_path / "missing.yml")]).scan(tmp_path, [Path("a.py")])
