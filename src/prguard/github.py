from __future__ import annotations

from typing import Any
from urllib.parse import quote

import httpx

from prguard.diff import FileDiff, parse_patch


class GitHubError(RuntimeError):
    def __init__(self, message: str, status: int) -> None:
        super().__init__(message)
        self.status = status


class GitHub:
    def __init__(
        self,
        token: str,
        repo: str,
        api_url: str = "https://api.github.com",
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        self.repo = repo
        self.http = httpx.Client(
            base_url=api_url,
            headers={
                "Authorization": f"Bearer {token}",
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
                "User-Agent": "prguard",
            },
            timeout=30,
            transport=transport,
        )

    def _request(self, method: str, url: str, **kwargs: Any) -> httpx.Response:
        response = self.http.request(method, url, **kwargs)
        if response.status_code >= 400:
            try:
                detail = response.json().get("message", "")
            except ValueError:
                detail = response.text[:200]
            raise GitHubError(
                f"{method} {url} failed with {response.status_code}: {detail}", response.status_code
            )
        return response

    def _paginate(self, url: str) -> list[dict[str, Any]]:
        items: list[dict[str, Any]] = []
        next_url: str | None = url
        params: dict[str, Any] | None = {"per_page": 100}
        while next_url:
            response = self._request("GET", next_url, params=params)
            items.extend(response.json())
            # the next link already carries the query string
            params = None
            next_url = response.links.get("next", {}).get("url")
        return items

    def pull_request_files(self, number: int) -> list[FileDiff]:
        raw = self._paginate(f"/repos/{self.repo}/pulls/{number}/files")
        return [parse_patch(f["filename"], f["status"], f.get("patch")) for f in raw]

    def file_content(self, path: str, ref: str) -> str | None:
        response = self.http.get(
            f"/repos/{self.repo}/contents/{quote(path)}",
            params={"ref": ref},
            headers={"Accept": "application/vnd.github.raw+json"},
        )
        if response.status_code == 404:
            return None
        if response.status_code >= 400:
            raise GitHubError(f"couldn't fetch {path}@{ref}: {response.status_code}", response.status_code)
        try:
            return response.content.decode("utf-8")
        except UnicodeDecodeError:
            return None

    def review_comment_bodies(self, number: int) -> list[str]:
        return [c.get("body", "") for c in self._paginate(f"/repos/{self.repo}/pulls/{number}/comments")]

    def create_review(
        self, number: int, commit_id: str, body: str, comments: list[dict[str, object]]
    ) -> None:
        # always COMMENT, never APPROVE or REQUEST_CHANGES: the bot doesn't get a vote
        self._request(
            "POST",
            f"/repos/{self.repo}/pulls/{number}/reviews",
            json={"commit_id": commit_id, "event": "COMMENT", "body": body, "comments": comments},
        )


class GitHubContent:
    """File contents at the PR head, fetched on demand."""

    def __init__(self, gh: GitHub, ref: str) -> None:
        self.gh = gh
        self.ref = ref

    def get(self, path: str) -> str | None:
        return self.gh.file_content(path, self.ref)
