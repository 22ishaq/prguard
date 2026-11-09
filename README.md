# PRGuard

[![CI](https://github.com/22ishaq/prguard/actions/workflows/ci.yml/badge.svg)](https://github.com/22ishaq/prguard/actions/workflows/ci.yml)

A GitHub Action that reviews pull requests for security problems and missing tests. It uses Claude for the review and Semgrep to keep it honest.

Still a work in progress, see the [roadmap](#roadmap).

## What it does

On every pull request PRGuard:

1. Pulls the diff from the GitHub API and drops lockfiles, vendored code, binaries and anything over the size limits.
2. **Strips secrets from the diff before it leaves the runner.** Known token formats (AWS, GitHub, Anthropic, OpenAI, Stripe, Slack, Google, JWTs), private key blocks, passwords in URLs, `password = "..."` style assignments and random-looking blobs are all replaced with `[REDACTED:kind]`. Files like `.env` and `*.pem` are never sent at all. Each real secret it finds is also reported as a finding.
3. Runs Semgrep on the changed files at the PR's head commit and keeps the results that land on added lines.
4. Sends the redacted diff, with Semgrep's results as hints, to Claude and asks for findings as structured JSON: file, line range, severity, confidence, explanation and an optional suggested fix.
5. Throws away anything that points outside the diff, since GitHub can't attach a comment there and it usually means the model got confused.
6. **Checks every suggested fix with static analysis before posting it.** The fix is applied to a copy of the file, Python fixes are compiled with `ast.parse`, and the copy is scanned with Semgrep. If the patched lines don't parse, or Semgrep still flags them, the suggestion is removed and the comment says why.
7. Posts one review with inline comments, plus a job summary. Findings carry a hidden fingerprint, so pushing more commits doesn't repost the same comments.

Here's what it finds in [`tests/fixtures/sample.diff`](tests/fixtures/sample.diff) with `--no-llm` (secret scan and Semgrep only):

```
app/runner.py:4: [high/security] Hardcoded secret (github-token) (secrets)
app/runner.py:8: [high/security] Subprocess shell true (semgrep)
Source files changed but no tests did: `app/runner.py`.
1 possible secret(s) were redacted before the diff was sent to the model.
```

The f-string SQL query on line 12 isn't matched by the Semgrep rules. Catching that kind of thing is the LLM's job.

## Usage

```yaml
# .github/workflows/prguard.yml
name: PRGuard
on:
  pull_request:

permissions:
  contents: read
  pull-requests: write

jobs:
  review:
    runs-on: ubuntu-latest
    steps:
      - uses: 22ishaq/prguard@main
        with:
          anthropic-api-key: ${{ secrets.ANTHROPIC_API_KEY }}
          fail-on: high
```

No checkout step is needed. PRGuard reads everything through the API.

| Input | Default | |
|---|---|---|
| `anthropic-api-key` | | without it only the secret scan and Semgrep run |
| `github-token` | `github.token` | needs `pull-requests: write` |
| `model` | `claude-opus-5-5` | |
| `effort` | `high` | `low`, `medium`, `high`, `xhigh`, `max` |
| `fail-on` | `none` | fail the check when anything at this severity or above is found |
| `config` | `.prguard.yml` | |
| `semgrep-version` | `1.184.0` | |

### Config file

```yaml
# .prguard.yml
effort: high
fail_on: high
min_severity: low
min_confidence: medium   # low-confidence LLM findings are dropped unless Semgrep agrees
max_files: 50
max_file_chars: 20000
max_total_chars: 150000
ignore:                  # added to the built-in ignores (lockfiles, vendor/, dist/, images...)
  - "docs/**"
test_patterns:           # what counts as a test file for the missing-tests check
  - "**/tests/**"
  - "**/test_*.py"
semgrep:
  enabled: true
  configs:
    - p/python
    - .semgrep/rules.yml
```

The config is read from the **base** branch of the pull request, so a PR can't change it to skip its own review.

### Running it locally

```bash
pip install -e .
git diff main | prguard local - --no-llm
```

Drop `--no-llm` to include the Claude review. It picks up `ANTHROPIC_API_KEY` from the environment. Add `--json` for machine readable output.

## Security model

A tool that reads untrusted code and has a write token needs to be careful about what it trusts.

- **The diff is untrusted.** The system prompt tells the model the diff was written by whoever opened the PR and never to follow instructions inside it. The model's output is also boxed in. It can only produce JSON in a fixed schema, findings must point at lines in the diff, and the review is always posted as `COMMENT`, never `APPROVE`. So the worst a prompt injection can do is get a misleading comment posted or a real one left out. It can't merge anything.
- **Secrets are removed before the API call**, not after. Redaction deliberately overdoes it. A false positive costs the model some context, but a miss sends a key to a third party.
- **Suggested fixes are never shown unchecked.** If Semgrep isn't available, suggestions are dropped instead of posted unverified.
- **Fork PRs** don't get repository secrets, so PRGuard runs without the LLM there. Don't switch to `pull_request_target` to get around that, since it would run with secrets on code from the fork.
- Semgrep runs with `--metrics=off`.
- Every action used here is pinned to a full commit SHA, and the Semgrep job in CI fails if one isn't. Dependabot bumps the pins.

## Model call

The review is one streamed Messages API call to `claude-opus-5-5` with `output_config.format` set to a JSON schema, so the response always parses. It also sends `fallbacks: "default"`: security reviews sometimes trip the safety classifiers, and this lets the API retry on a fallback model instead of failing. The SDK retries 429s and 5xx errors with backoff. If the call still fails, is refused or gets cut off, the review goes ahead with the secret and Semgrep findings and says the LLM step didn't run. An API outage shouldn't block merges.

The prompt asks the model to report everything it suspects and to set confidence honestly. The filtering happens afterwards, in code (`min_confidence`, `min_severity`), where it's visible and configurable.

## Development

```bash
python -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"
pipx install semgrep    # optional, the real-semgrep tests skip without it
ruff check . && ruff format --check . && mypy && pytest
```

The LLM is behind a small `Reviewer` protocol, so the tests use a fake one and never call the API. The tests cover redaction (including checking that secrets don't appear in the prompt), diff parsing and line mapping, suggestion verification against real Semgrep, the GitHub client via `httpx.MockTransport`, and the whole action end to end against a fake GitHub API.

CI runs ruff, mypy and pytest on Python 3.11 to 3.13, a Semgrep scan of the source and workflows, `pip-audit` on the installed dependencies, and GitHub's dependency review on PRs. PRGuard also reviews its own pull requests.

## Roadmap

- [x] secret redaction before the model call
- [x] Semgrep hints and suggestion verification
- [x] dedupe across pushes
- [x] config read from the base branch
- [ ] only review commits pushed since the last review
- [ ] resolve PRGuard's own threads once a finding is fixed
- [ ] SARIF output for GitHub code scanning
- [ ] report token usage and cost per review
- [ ] other model providers behind the `Reviewer` interface
