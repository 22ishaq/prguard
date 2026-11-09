from __future__ import annotations

import argparse
import json
import logging
import os
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path

from prguard import render
from prguard.config import ConfigError, Settings, load_settings, parse_settings
from prguard.diff import parse_git_diff
from prguard.github import GitHub, GitHubContent, GitHubError
from prguard.llm import make_reviewer
from prguard.models import Finding
from prguard.review import ReviewResult, run_review
from prguard.semgrep import Semgrep

log = logging.getLogger("prguard")


class LocalContent:
    def __init__(self, root: Path) -> None:
        self.root = root.resolve()

    def get(self, path: str) -> str | None:
        target = (self.root / path).resolve()
        # paths come from the diff, so don't let one walk out of the repo
        if not target.is_relative_to(self.root) or not target.is_file():
            return None
        try:
            return target.read_text()
        except UnicodeDecodeError:
            return None


def make_scanner(settings: Settings) -> Semgrep | None:
    if not settings.semgrep_enabled:
        return None
    if not Semgrep.available():
        log.warning("semgrep isn't installed, so static analysis and suggestion checks are off")
        return None
    return Semgrep(settings.semgrep_configs)


def exit_code(result: ReviewResult, settings: Settings) -> int:
    worst = render.worst(result.findings)
    if settings.fail_on is not None and worst is not None and worst >= settings.fail_on:
        log.error("failing: found a %s issue and fail_on is %s", worst.label(), settings.fail_on.label())
        return 1
    return 0


def publish(gh: GitHub, number: int, head_sha: str, result: ReviewResult) -> list[Finding]:
    seen = render.posted_fingerprints(gh.review_comment_bodies(number))
    new = [f for f in result.findings if f.fingerprint() not in seen]
    if not new:
        log.info("no new findings to post")
        return []

    body = render.summary_body(result, new)
    try:
        gh.create_review(number, head_sha, body, [render.review_comment(f) for f in new])
    except GitHubError as e:
        if e.status != 422:
            raise
        # GitHub rejects the whole review if one comment points at a line it doesn't
        # consider part of the diff. Better to post everything in the body than nothing.
        log.warning("inline comments were rejected (%s), posting a single review instead", e)
        gh.create_review(number, head_sha, body + "\n\n" + render.findings_list(new), [])
    return new


def run_github(env: Mapping[str, str]) -> int:
    event = json.loads(Path(env["GITHUB_EVENT_PATH"]).read_text())
    pr = event.get("pull_request")
    if not pr:
        log.warning("this isn't a pull_request event, nothing to review")
        return 0

    gh = GitHub(
        env["GITHUB_TOKEN"], env["GITHUB_REPOSITORY"], env.get("GITHUB_API_URL", "https://api.github.com")
    )
    number, head_sha = int(pr["number"]), pr["head"]["sha"]

    # Read the config from the base branch, not the PR. Otherwise a PR could add
    # `ignore: ["**"]` and review itself into silence.
    config_path = env.get("PRGUARD_CONFIG") or ".prguard.yml"
    settings = parse_settings(gh.file_content(config_path, pr["base"]["sha"]), env, source=config_path)

    api_key = env.get("ANTHROPIC_API_KEY", "").strip()
    if not api_key:
        # e.g. a PR from a fork, which doesn't get repository secrets
        log.warning("ANTHROPIC_API_KEY isn't set, running the secret and Semgrep checks only")
    reviewer = make_reviewer(api_key, settings.model, settings.effort) if api_key else None

    files = gh.pull_request_files(number)
    log.info("reviewing %d changed file(s) in #%d", len(files), number)
    result = run_review(
        files,
        GitHubContent(gh, head_sha),
        settings,
        reviewer,
        make_scanner(settings),
        title=pr.get("title", ""),
    )

    posted = publish(gh, number, head_sha, result)
    log.info("%d finding(s), %d newly posted", len(result.findings), len(posted))
    if summary_path := env.get("GITHUB_STEP_SUMMARY"):
        with open(summary_path, "a") as fh:
            fh.write(render.step_summary(result))
    return exit_code(result, settings)


def run_local(args: argparse.Namespace) -> int:
    text = sys.stdin.read() if args.diff == "-" else Path(args.diff).read_text()
    settings = load_settings(Path(args.config))
    # with no key passed the SDK falls back to ANTHROPIC_API_KEY or an `ant auth login` profile
    reviewer = None if args.no_llm else make_reviewer(None, settings.model, settings.effort)
    result = run_review(
        parse_git_diff(text), LocalContent(Path(args.root)), settings, reviewer, make_scanner(settings)
    )

    if args.json:
        print(
            json.dumps(
                [
                    {
                        **{k: v for k, v in vars(f).items() if k not in ("severity", "confidence")},
                        "severity": f.severity.label(),
                        "confidence": f.confidence.name.lower(),
                    }
                    for f in result.findings
                ],
                indent=2,
            )
        )
    else:
        print(render.text_report(result))
    return exit_code(result, settings)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="prguard", description=__doc__)
    parser.add_argument("-v", "--verbose", action="store_true")
    sub = parser.add_subparsers(dest="command")
    sub.add_parser("github", help="review the pull request from GITHUB_EVENT_PATH (what the action runs)")
    local = sub.add_parser("local", help="review a git diff and print the findings")
    local.add_argument("diff", help="file containing `git diff` output, or - for stdin")
    local.add_argument("--root", default=".", help="checkout to read full files from (default: .)")
    local.add_argument("--config", default=".prguard.yml")
    local.add_argument("--json", action="store_true", help="print findings as JSON")
    local.add_argument("--no-llm", action="store_true", help="only run the secret and Semgrep checks")
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO, format="%(levelname)s %(message)s"
    )
    # the anthropic and httpx loggers are chatty at INFO
    logging.getLogger("httpx").setLevel(logging.WARNING)

    try:
        if args.command == "local":
            return run_local(args)
        return run_github(os.environ)
    except (ConfigError, GitHubError) as e:
        log.error("%s", e)
        return 2
