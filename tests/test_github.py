import json

import httpx

from prguard.github import GitHub, GitHubError


def client(handler) -> GitHub:  # type: ignore[no-untyped-def]
    return GitHub("t0ken", "octo/repo", transport=httpx.MockTransport(handler))


def test_follows_pagination() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.headers["Authorization"] == "Bearer t0ken"
        if request.url.params.get("page") == "2":
            return httpx.Response(
                200, json=[{"filename": "b.py", "status": "added", "patch": "@@ -0,0 +1 @@\n+b"}]
            )
        link = '<https://api.github.com/repos/octo/repo/pulls/7/files?per_page=100&page=2>; rel="next"'
        return httpx.Response(
            200,
            headers={"Link": link},
            json=[{"filename": "a.py", "status": "modified", "patch": "@@ -1 +1 @@\n-a\n+A"}],
        )

    files = client(handler).pull_request_files(7)

    assert [(f.path, f.added) for f in files] == [("a.py", {1: "A"}), ("b.py", {1: "b"})]


def test_file_content_at_ref() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("missing.py"):
            return httpx.Response(404, json={"message": "Not Found"})
        assert request.url.params["ref"] == "abc123"
        assert request.headers["Accept"] == "application/vnd.github.raw+json"
        return httpx.Response(200, content=b"print('hi')\n")

    gh = client(handler)

    assert gh.file_content("src/app.py", "abc123") == "print('hi')\n"
    assert gh.file_content("missing.py", "abc123") is None


def test_binary_content_is_skipped() -> None:
    assert client(lambda r: httpx.Response(200, content=b"\xff\xd8\xff")).file_content("a.jpg", "x") is None


def test_review_is_always_a_comment() -> None:
    sent = []

    def handler(request: httpx.Request) -> httpx.Response:
        sent.append(json.loads(request.content))
        return httpx.Response(200, json={})

    client(handler).create_review(7, "abc123", "body", [{"path": "a.py", "line": 1, "body": "x"}])

    assert sent == [
        {
            "commit_id": "abc123",
            "event": "COMMENT",
            "body": "body",
            "comments": [{"path": "a.py", "line": 1, "body": "x"}],
        }
    ]


def test_errors_carry_the_status() -> None:
    gh = client(lambda r: httpx.Response(422, json={"message": "Line could not be resolved"}))

    try:
        gh.create_review(7, "abc", "body", [])
    except GitHubError as e:
        assert e.status == 422
        assert "Line could not be resolved" in str(e)
    else:
        raise AssertionError("expected GitHubError")
