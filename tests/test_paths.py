import pytest

from prguard.paths import matches


@pytest.mark.parametrize(
    ("path", "pattern", "expected"),
    [
        ("test_app.py", "**/test_*.py", True),
        ("pkg/tests/test_app.py", "**/test_*.py", True),
        ("pkg/app.py", "**/test_*.py", False),
        ("docs/a/b/c.md", "docs/**", True),
        ("src/docs/a.md", "docs/**", False),
        ("yarn.lock", "**/*.lock", True),
        ("web/node_modules/x/index.js", "**/node_modules/**", True),
        ("src/app.test.ts", "**/*.test.[jt]s", True),
        ("src/app.test.cs", "**/*.test.[jt]s", False),
        ("a.py", "*.py", True),
        ("src/a.py", "*.py", False),
    ],
)
def test_glob_matching(path: str, pattern: str, expected: bool) -> None:
    assert matches(path, pattern) is expected
