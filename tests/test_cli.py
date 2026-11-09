import json
from pathlib import Path
from typing import Any

import httpx
import pytest
from conftest import FakeReviewer

from prguard import cli
from prguard.github import GitHub
from prguard.models import Confidence, Finding, Severity

APP_PATCH = (
    "@@ -1,2 +1,4 @@\n import subprocess\n+\n+def run(cmd):\n+    return subprocess.run(cmd, shell=True)"
)
APP_SOURCE = "import subprocess\n\ndef run(cmd):\n    return subprocess.run(cmd, shell=True)\n"


class FakeGitHubAPI:
    def __init__(
        self,
        existing_comments: list[str] | None = None,
        reject_inline: bool = False,
        config: dict[str, str] | None = None,
    ) -> None:
        self.existing_comments = existing_comments or []
        self.reject_inline = reject_inline
        self.config = config or {}
        self.reviews: list[dict[str, Any]] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path == "/repos/octo/repo/pulls/7/files":
            return httpx.Response(
                200, json=[{"filename": "app.py", "status": "modified", "patch": APP_PATCH}]
            )
        if path == "/repos/octo/repo/contents/.prguard.yml":
            ref = request.url.params["ref"]
            if ref in self.config:
                return httpx.Response(200, content=self.config[ref].encode())
            return httpx.Response(404, json={"message": "Not Found"})
        if path == "/repos/octo/repo/contents/app.py":
            return httpx.Response(200, content=APP_SOURCE.encode())
        if path == "/repos/octo/repo/pulls/7/comments":
            return httpx.Response(200, json=[{"body": b} for b in self.existing_comments])
        if path == "/repos/octo/repo/pulls/7/reviews" and request.method == "POST":
            payload = json.loads(request.content)
            if self.reject_inline and payload["comments"]:
                return httpx.Response(422, json={"message": "Line could not be resolved"})
            self.reviews.append(payload)
            return httpx.Response(200, json={})
        return httpx.Response(404, json={"message": f"unexpected {request.method} {path}"})


def shell_finding() -> Finding:
    return Finding(
        "app.py", 4, "security", Severity.HIGH, Confidence.HIGH, "Shell injection", "cmd is user input"
    )


@pytest.fixture
def action_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> dict[str, str]:
    event = {
        "pull_request": {
            "number": 7,
            "title": "Add runner",
            "head": {"sha": "abc123"},
            "base": {"sha": "base456"},
        }
    }
    (tmp_path / "event.json").write_text(json.dumps(event))
    monkeypatch.chdir(tmp_path)
    return {
        "GITHUB_EVENT_PATH": str(tmp_path / "event.json"),
        "GITHUB_REPOSITORY": "octo/repo",
        "GITHUB_TOKEN": "t0ken",
        "GITHUB_STEP_SUMMARY": str(tmp_path / "summary.md"),
        "ANTHROPIC_API_KEY": "test-key",
    }


def wire(monkeypatch: pytest.MonkeyPatch, api: FakeGitHubAPI, reviewer: FakeReviewer) -> None:
    monkeypatch.setattr(
        cli, "GitHub", lambda token, repo, url: GitHub(token, repo, url, httpx.MockTransport(api))
    )
    monkeypatch.setattr(cli, "make_reviewer", lambda key, model, effort: reviewer)
    monkeypatch.setattr(cli, "make_scanner", lambda settings: None)


def test_posts_a_review_with_inline_comments(
    action_env: dict[str, str], monkeypatch: pytest.MonkeyPatch
) -> None:
    api = FakeGitHubAPI()
    wire(monkeypatch, api, FakeReviewer([shell_finding()], summary="Risky."))

    assert cli.run_github(action_env) == 0

    (review,) = api.reviews
    assert review["commit_id"] == "abc123"
    assert review["event"] == "COMMENT"
    assert "PRGuard found 1 high" in review["body"]
    assert "Risky." in review["body"]
    (comment,) = review["comments"]
    assert (comment["path"], comment["line"], comment["side"]) == ("app.py", 4, "RIGHT")
    assert "Shell injection" in Path(action_env["GITHUB_STEP_SUMMARY"]).read_text()


def test_doesnt_repost_existing_findings(action_env: dict[str, str], monkeypatch: pytest.MonkeyPatch) -> None:
    marker = f"<!-- prguard:{shell_finding().fingerprint()} -->"
    api = FakeGitHubAPI(existing_comments=[f"old comment\n{marker}"])
    wire(monkeypatch, api, FakeReviewer([shell_finding()]))

    cli.run_github(action_env)

    assert api.reviews == []


def test_falls_back_to_a_plain_review(action_env: dict[str, str], monkeypatch: pytest.MonkeyPatch) -> None:
    api = FakeGitHubAPI(reject_inline=True)
    wire(monkeypatch, api, FakeReviewer([shell_finding()]))

    cli.run_github(action_env)

    (review,) = api.reviews
    assert review["comments"] == []
    assert "`app.py:4` Shell injection" in review["body"]


def test_fail_on_sets_the_exit_code(action_env: dict[str, str], monkeypatch: pytest.MonkeyPatch) -> None:
    wire(monkeypatch, FakeGitHubAPI(), FakeReviewer([shell_finding()]))

    assert cli.run_github({**action_env, "PRGUARD_FAIL_ON": "high"}) == 1
    assert cli.run_github({**action_env, "PRGUARD_FAIL_ON": "critical"}) == 0


def test_runs_without_an_api_key(action_env: dict[str, str], monkeypatch: pytest.MonkeyPatch) -> None:
    reviewer = FakeReviewer([shell_finding()])
    wire(monkeypatch, FakeGitHubAPI(), reviewer)

    assert cli.run_github({**action_env, "ANTHROPIC_API_KEY": ""}) == 0
    assert reviewer.prompts == []


def test_config_comes_from_the_base_branch(
    action_env: dict[str, str], monkeypatch: pytest.MonkeyPatch
) -> None:
    # the PR's own copy of the config tries to ignore everything; the base branch's doesn't
    api = FakeGitHubAPI(config={"abc123": "ignore: ['**']\n", "base456": "fail_on: high\n"})
    wire(monkeypatch, api, FakeReviewer([shell_finding()]))

    assert cli.run_github(action_env) == 1
    assert len(api.reviews) == 1


def test_ignores_other_events(tmp_path: Path) -> None:
    (tmp_path / "event.json").write_text(json.dumps({"push": {}}))

    assert cli.run_github({"GITHUB_EVENT_PATH": str(tmp_path / "event.json")}) == 0


def test_local_content_stays_inside_the_root(tmp_path: Path) -> None:
    (tmp_path / "repo").mkdir()
    (tmp_path / "repo" / "a.py").write_text("x = 1\n")
    (tmp_path / "secret.txt").write_text("nope")
    content = cli.LocalContent(tmp_path / "repo")

    assert content.get("a.py") == "x = 1\n"
    assert content.get("../secret.txt") is None
    assert content.get("missing.py") is None


def test_local_mode_without_the_llm(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    diff = tmp_path / "change.diff"
    diff.write_text(
        "diff --git a/cfg.py b/cfg.py\nnew file mode 100644\n--- /dev/null\n+++ b/cfg.py\n"
        "@@ -0,0 +1 @@\n+KEY = 'AKIA"
        "Z5FAKEKEY1234567'\n"
    )
    config = tmp_path / ".prguard.yml"
    config.write_text("semgrep:\n  enabled: false\n")

    code = cli.main(["local", str(diff), "--root", str(tmp_path), "--config", str(config), "--no-llm"])

    out = capsys.readouterr().out
    assert code == 0
    assert "cfg.py:1: [high/security] Hardcoded secret (aws-access-key-id)" in out
    assert "Z5FAKEKEY1234567" not in out
