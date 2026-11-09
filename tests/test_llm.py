import json
from types import SimpleNamespace
from typing import Any

import anthropic
import httpx2
import pytest
from conftest import new_file

from prguard.llm import FALLBACK_BETA, ClaudeReviewer, ReviewFailed, build_prompt, parse_review
from prguard.models import Confidence, Severity
from prguard.semgrep import SemgrepResult

GOOD = {
    "summary": "One injection risk.",
    "findings": [
        {
            "path": "app.py",
            "start_line": 2,
            "line": 2,
            "category": "security",
            "severity": "high",
            "confidence": "medium",
            "title": "SQL built with string formatting",
            "explanation": "user input goes straight into the query",
            "suggestion": "",
        },
        {
            "path": "app.py",
            "start_line": 3,
            "line": 4,
            "category": "missing-tests",
            "severity": "low",
            "confidence": "high",
            "title": "No test for the empty case",
            "explanation": "...",
            "suggestion": "if not rows:\n    return []",
        },
    ],
}


class FakeStream:
    def __init__(self, message: Any) -> None:
        self.message = message

    def __enter__(self) -> "FakeStream":
        return self

    def __exit__(self, *exc: object) -> None:
        return None

    def get_final_message(self) -> Any:
        return self.message


class FakeMessages:
    def __init__(self, message: Any = None, error: Exception | None = None) -> None:
        self.message = message
        self.error = error
        self.calls: list[dict[str, Any]] = []

    def stream(self, **kwargs: Any) -> FakeStream:
        self.calls.append(kwargs)
        if self.error:
            raise self.error
        return FakeStream(self.message)


def reply(data: object, stop_reason: str = "end_turn") -> SimpleNamespace:
    text = data if isinstance(data, str) else json.dumps(data)
    return SimpleNamespace(
        stop_reason=stop_reason,
        content=[SimpleNamespace(type="thinking", thinking=""), SimpleNamespace(type="text", text=text)],
        usage=SimpleNamespace(input_tokens=100, output_tokens=50),
    )


def reviewer(messages: FakeMessages) -> ClaudeReviewer:
    client = SimpleNamespace(beta=SimpleNamespace(messages=messages))
    return ClaudeReviewer(client, model="claude-opus-5-5", effort="high")  # type: ignore[arg-type]


def test_parses_structured_findings() -> None:
    review = reviewer(FakeMessages(reply(GOOD))).review("diff")

    first, second = review.findings
    assert review.summary == "One injection risk."
    assert (first.path, first.line, first.start_line) == ("app.py", 2, None)
    assert first.severity is Severity.HIGH and first.confidence is Confidence.MEDIUM
    assert first.suggestion is None
    assert (second.start_line, second.line) == (3, 4)
    assert second.suggestion == "if not rows:\n    return []"


def test_sends_model_effort_schema_and_fallback() -> None:
    messages = FakeMessages(reply(GOOD))

    reviewer(messages).review("the diff")

    (call,) = messages.calls
    assert call["model"] == "claude-opus-5-5"
    assert call["output_config"]["effort"] == "high"
    assert call["output_config"]["format"]["type"] == "json_schema"
    assert call["fallbacks"] == "default"
    assert call["betas"] == [FALLBACK_BETA]
    assert call["messages"] == [{"role": "user", "content": "the diff"}]
    assert "untrusted" in call["system"]


def test_refusal_is_an_error() -> None:
    with pytest.raises(ReviewFailed, match="declined"):
        reviewer(FakeMessages(reply("", stop_reason="refusal"))).review("diff")


def test_truncated_output_is_an_error() -> None:
    with pytest.raises(ReviewFailed, match="cut off"):
        reviewer(FakeMessages(reply('{"summary": "x", "find', stop_reason="max_tokens"))).review("diff")


def test_api_errors_become_review_failures() -> None:
    request = httpx2.Request("POST", "https://api.anthropic.com/v1/messages")
    error = anthropic.InternalServerError(
        "overloaded", response=httpx2.Response(529, request=request), body=None
    )

    with pytest.raises(ReviewFailed, match="529"):
        reviewer(FakeMessages(error=error)).review("diff")


def test_connection_errors_become_review_failures() -> None:
    error = anthropic.APIConnectionError(
        request=httpx2.Request("POST", "https://api.anthropic.com/v1/messages")
    )

    with pytest.raises(ReviewFailed, match="reach"):
        reviewer(FakeMessages(error=error)).review("diff")


def test_one_bad_item_doesnt_sink_the_rest() -> None:
    data = {
        "summary": "",
        "findings": [dict(GOOD["findings"][0], severity="apocalyptic"), GOOD["findings"][1]],
    }

    review = parse_review(data)

    assert [f.title for f in review.findings] == ["No test for the empty case"]


def test_prompt_has_line_numbers_tests_and_static_analysis() -> None:
    diff = new_file("app.py", ["import os", "os.system(cmd)"])
    hint = SemgrepResult("dangerous-system-call", "app.py", 2, 2, Severity.HIGH, Confidence.HIGH, "os.system")

    prompt = build_prompt([diff], [hint], [], title="Add runner")

    assert "Pull request title: Add runner" in prompt
    assert "No test files were changed" in prompt
    assert "- app.py:2 [dangerous-system-call] os.system" in prompt
    assert "    2 + os.system(cmd)" in prompt
    assert prompt.index("<static_analysis>") < prompt.index("<diff>")
