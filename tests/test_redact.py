import pytest

from prguard.diff import parse_patch
from prguard.redact import is_sensitive_file, looks_like_placeholder, redact_file, redact_text


@pytest.mark.parametrize(
    ("line", "kind"),
    [
        ('AWS_ACCESS_KEY_ID = "AKIA' + 'Z5FAKEKEY1234567"', "aws-access-key-id"),
        ("token: ghp_" + "a" * 36, "github-token"),
        ("export KEY=sk-ant-api03-" + "x1Y2z3" * 6, "anthropic-api-key"),
        ("OPENAI_API_KEY=sk-proj-" + "Ab3" * 10, "openai-api-key"),
        ("stripe.api_key = 'sk_live_" + "4eC39HqLyjWDarjtT1zdp7dc" + "'", "stripe-key"),
        ("SLACK=xoxb-" + "123456789012-abcdefghij", "slack-token"),
        ("key=AIza" + "S" * 35, "google-api-key"),
        (
            "Authorization: eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U",
            "jwt",
        ),
        ('DATABASE_URL = "postgres://app:s3cr3tpass@db:5432/app"', "url-password"),
        ('db_password = "hunter2hunter2"', "hardcoded-credential"),
        ('"client_secret": "Zq81hdkK1023"', "hardcoded-credential"),
    ],
)
def test_redacts_known_secret_formats(line: str, kind: str) -> None:
    redacted, found = redact_text(line)

    assert f"[REDACTED:{kind}]" in redacted
    assert kind in [k for k, _ in found]


def test_url_redaction_keeps_the_rest_of_the_url() -> None:
    redacted, _ = redact_text("postgres://app:s3cr3tpass@db:5432/app")

    assert redacted == "postgres://app:[REDACTED:url-password]@db:5432/app"


@pytest.mark.parametrize(
    "line",
    [
        'password = os.environ["DB_PASSWORD"]',
        'password = "changeme"',
        'api_key = "<your api key>"',
        'token = "${TOKEN}"',
        "def check_password(user, password):",
        "user_id = request.args.get('user_id')",
        "test_reusing_a_key_for_a_different_payment_is_rejected",
        "return self.handlesLargeInputsQuickly2",
    ],
)
def test_leaves_ordinary_code_alone(line: str) -> None:
    assert redact_text(line) == (line, [])


def test_random_looking_blobs_are_redacted_but_not_reported() -> None:
    redacted, found = redact_text('SIGNING = "q8Zr1Lx0pV3nT6bW9yK2mH5dF7gJ4sA1"')

    assert "q8Zr1Lx0pV3nT6bW9yK2mH5dF7gJ4sA1" not in redacted
    assert found and not any(reportable for _, reportable in found)


def test_placeholder_detection() -> None:
    assert looks_like_placeholder("xxxxxxxx")
    assert looks_like_placeholder("your-token-here")
    assert not looks_like_placeholder("hunter2hunter2")


def test_private_key_blocks_are_removed_entirely() -> None:
    patch = "\n".join(
        [
            "@@ -0,0 +1,6 @@",
            "+KEY = '''",
            "+-----BEGIN RSA PRIVATE KEY-----",
            "+MIIEowIBAAKCAQEAu1SU1LfVLPHCozMxH2Mo4lgOEePzNm0tRgeLezV6ffAt0gun",
            "+VTLw7onLRnrq0/IzW7yWR7QkrmBL7jTKEn5u+qKhbwKfBstIs+bMY2Zkp18gnTxK",
            "+-----END RSA PRIVATE KEY-----",
            "+'''",
        ]
    )

    clean, redactions = redact_file(parse_patch("keys.py", "added", patch))

    assert [ln.text for ln in clean.lines[1:]] == ["KEY = '''"] + ["[REDACTED:private-key]"] * 4 + ["'''"]
    assert [(r.line, r.kind) for r in redactions] == [(2, "private-key")]


def test_redactions_carry_new_file_line_numbers() -> None:
    patch = "@@ -1,2 +1,3 @@\n import os\n-old = 1\n+TOKEN = 'ghp_" + "b" * 36 + "'\n+x = 2"

    _, redactions = redact_file(parse_patch("settings.py", "modified", patch))

    assert [(r.line, r.kind) for r in redactions] == [(2, "github-token")]


@pytest.mark.parametrize(
    ("path", "sensitive"),
    [
        (".env", True),
        ("config/.env.production", True),
        (".env.example", False),
        ("deploy/server.pem", True),
        ("home/.ssh/id_rsa", True),
        ("src/env.py", False),
        ("src/keys.py", False),
    ],
)
def test_sensitive_files(path: str, sensitive: bool) -> None:
    assert is_sensitive_file(path) is sensitive
