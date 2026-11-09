from pathlib import Path

import pytest

from prguard.config import DEFAULT_IGNORE, ConfigError, load_settings
from prguard.models import Confidence, Severity


def test_defaults_without_a_file(tmp_path: Path) -> None:
    settings = load_settings(tmp_path / "missing.yml", env={})

    assert settings.model == "claude-opus-5-5"
    assert settings.fail_on is None
    assert settings.semgrep_configs == ["p/default"]


def test_reads_the_config_file(tmp_path: Path) -> None:
    path = tmp_path / ".prguard.yml"
    path.write_text(
        "effort: medium\nfail_on: high\nmin_confidence: low\nignore: ['docs/**']\n"
        "semgrep:\n  configs: [p/python, .semgrep/rules.yml]\n"
    )

    settings = load_settings(path, env={})

    assert settings.effort == "medium"
    assert settings.fail_on is Severity.HIGH
    assert settings.min_confidence is Confidence.LOW
    assert settings.ignore == DEFAULT_IGNORE + ["docs/**"]
    assert settings.semgrep_configs == ["p/python", ".semgrep/rules.yml"]


def test_action_inputs_win(tmp_path: Path) -> None:
    path = tmp_path / ".prguard.yml"
    path.write_text("fail_on: high\nmodel: claude-sonnet-5-5\n")

    settings = load_settings(
        path, env={"PRGUARD_FAIL_ON": "none", "PRGUARD_MODEL": "", "PRGUARD_EFFORT": "xhigh"}
    )

    assert settings.fail_on is None
    assert settings.model == "claude-sonnet-5-5"  # empty input means "not set"
    assert settings.effort == "xhigh"


@pytest.mark.parametrize(
    "content", ["effort: extreme\n", "fail_on: catastrophic\n", "max_files: 0\n", "- a\n- b\n"]
)
def test_rejects_bad_config(tmp_path: Path, content: str) -> None:
    path = tmp_path / ".prguard.yml"
    path.write_text(content)

    with pytest.raises(ConfigError):
        load_settings(path, env={})
