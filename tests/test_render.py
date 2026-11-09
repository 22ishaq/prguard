from prguard.models import Confidence, Finding, Severity
from prguard.render import comment_body, posted_fingerprints, review_comment


def finding(**overrides: object) -> Finding:
    values: dict[str, object] = {
        "path": "app.py",
        "line": 5,
        "category": "security",
        "severity": Severity.HIGH,
        "confidence": Confidence.MEDIUM,
        "title": "Shell injection",
        "explanation": "cmd is user controlled",
    }
    values.update(overrides)
    return Finding(**values)  # type: ignore[arg-type]


def test_comment_has_suggestion_block_and_marker() -> None:
    f = finding(suggestion="subprocess.run(cmd)", confirmed_by=["shell-true"])

    body = comment_body(f)

    assert body.startswith("**High · security: Shell injection**")
    assert "```suggestion\nsubprocess.run(cmd)\n```" in body
    assert "also flagged by `shell-true`" in body
    assert posted_fingerprints([body]) == {f.fingerprint()}


def test_suggestion_with_backticks_gets_a_longer_fence() -> None:
    body = comment_body(finding(suggestion='doc = """```py\nx\n```"""'))

    assert "````suggestion" in body


def test_dropped_suggestion_is_explained() -> None:
    body = comment_body(finding(suggestion_dropped="the patched file didn't parse"))

    assert "left out because the patched file didn't parse" in body


def test_fingerprint_ignores_line_numbers() -> None:
    assert finding(line=5).fingerprint() == finding(line=50).fingerprint()
    assert finding().fingerprint() != finding(title="Something else").fingerprint()


def test_multi_line_comment_payload() -> None:
    assert review_comment(finding(start_line=3)) == {
        "path": "app.py",
        "line": 5,
        "side": "RIGHT",
        "start_line": 3,
        "start_side": "RIGHT",
        "body": comment_body(finding(start_line=3)),
    }
