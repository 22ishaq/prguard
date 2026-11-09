from prguard.diff import parse_git_diff, parse_patch

PATCH = """\
@@ -10,5 +10,6 @@ def handler(request):
     user = request.user
-    query = "SELECT * FROM t WHERE id = %s" % request.args["id"]
+    query = "SELECT * FROM t WHERE id = %s"
+    rows = db.execute(query, (request.args["id"],))
     return render(rows)
@@ -40,2 +41,3 @@ def other():
     pass
+    log.info("done")
\\ No newline at end of file"""


def test_tracks_new_file_line_numbers() -> None:
    diff = parse_patch("app.py", "modified", PATCH)

    assert diff.added == {
        11: '    query = "SELECT * FROM t WHERE id = %s"',
        12: '    rows = db.execute(query, (request.args["id"],))',
        42: '    log.info("done")',
    }


def test_context_lines_are_commentable_but_removed_ones_are_not() -> None:
    diff = parse_patch("app.py", "modified", PATCH)

    assert diff.commentable == {10, 11, 12, 13, 41, 42}


def test_render_puts_line_numbers_in_the_gutter() -> None:
    rendered = parse_patch("app.py", "modified", PATCH).render().splitlines()

    assert rendered[0] == "--- app.py (modified)"
    assert rendered[2] == "   10       user = request.user"
    assert rendered[3].startswith("      - ")
    assert rendered[4].startswith("   11 + ")


def test_missing_patch_gives_empty_diff() -> None:
    assert parse_patch("logo.png", "added", None).lines == []


GIT_DIFF = """\
diff --git a/src/app.py b/src/app.py
index 1111111..2222222 100644
--- a/src/app.py
+++ b/src/app.py
@@ -1,2 +1,3 @@
 import os
+import subprocess
 print("hi")
diff --git a/new.py b/new.py
new file mode 100644
index 0000000..3333333
--- /dev/null
+++ b/new.py
@@ -0,0 +1,2 @@
+x = 1
+y = 2
diff --git a/gone.py b/gone.py
deleted file mode 100644
--- a/gone.py
+++ /dev/null
@@ -1 +0,0 @@
-print("bye")
diff --git a/old_name.py b/new_name.py
similarity index 90%
rename from old_name.py
rename to new_name.py
--- a/old_name.py
+++ b/new_name.py
@@ -1 +1 @@
-a = 1
+a = 2
"""


def test_splits_a_git_diff_into_files() -> None:
    files = {f.path: f for f in parse_git_diff(GIT_DIFF)}

    assert set(files) == {"src/app.py", "new.py", "gone.py", "new_name.py"}
    assert files["src/app.py"].added == {2: "import subprocess"}
    assert files["new.py"].status == "added"
    assert files["new.py"].added == {1: "x = 1", 2: "y = 2"}
    assert files["gone.py"].status == "removed"
    assert files["new_name.py"].status == "renamed"


def test_added_line_that_looks_like_a_header_stays_in_the_hunk() -> None:
    text = "diff --git a/x.md b/x.md\n--- a/x.md\n+++ b/x.md\n@@ -1 +1,2 @@\n a\n+++ not a header\n"

    (diff,) = parse_git_diff(text)

    assert diff.added == {2: "++ not a header"}
