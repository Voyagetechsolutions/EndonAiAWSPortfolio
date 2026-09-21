"""The secret-detection engine: signatures, entropy, placeholder suppression, redaction."""

import pytest

from endon_core.findings import Severity
from endon_dataprotection.secrets import SecretScanner, redact
from endon_dataprotection.secrets.entropy import is_high_entropy, shannon_entropy

# Clearly fake but format-valid secrets (none contain the word "example").
AWS_KEY = "AKIA2E0A8F3B7C9D1E5F"
GITHUB_TOKEN = "ghp_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"
STRIPE_LIVE = "sk_live_" + "4eC39HqLyjWDarjtT1zdp7dc"  # split so it isn't a scannable literal
DB_URL = "postgres://admin:sup3rs3cr3tPWzz@db.internal:5432/app"
PRIVATE_KEY = "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA7x9\n-----END RSA PRIVATE KEY-----"
AWS_SECRET = "wJalrXUtnFEMIK7MDENGbPxRfiCYzEXAMPLEKEYY"[:-11] + "Q2m5nZ8vT1kL"  # 40 base64 chars


@pytest.fixture
def scanner():
    return SecretScanner()


def test_signature_detects_aws_access_key(scanner):
    [match] = scanner.scan_text(f"the key is {AWS_KEY} ok")
    assert match.kind == "aws-access-key"
    assert match.severity is Severity.HIGH
    assert match.confidence == "signature"


@pytest.mark.parametrize(
    ("text", "kind", "severity"),
    [
        (PRIVATE_KEY, "private-key", Severity.CRITICAL),
        (f"token={GITHUB_TOKEN}", "github-token", Severity.HIGH),
        (f"STRIPE={STRIPE_LIVE}", "stripe-key", Severity.CRITICAL),
        (f"DATABASE_URL={DB_URL}", "db-connection-string", Severity.HIGH),
    ],
)
def test_signatures(scanner, text, kind, severity):
    kinds = {(m.kind, m.severity) for m in scanner.scan_text(text)}
    assert (kind, severity) in kinds


def test_redaction_never_contains_the_raw_secret(scanner):
    for secret in (AWS_KEY, GITHUB_TOKEN, STRIPE_LIVE):
        [match] = scanner.scan_text(secret)
        assert secret not in match.redacted
        assert secret not in match.to_dict()["redacted"]
        assert "sha256:" in match.redacted


def test_db_url_redacts_only_the_password(scanner):
    [match] = scanner.scan_text(f"DATABASE_URL={DB_URL}")
    assert "sup3rs3cr3tPWzz" not in match.redacted


def test_entropy_path_catches_secret_named_high_entropy_value(scanner):
    matches = scanner.scan_env("AWS_SECRET_ACCESS_KEY", AWS_SECRET, location="lambda:checkout")
    assert matches
    assert matches[0].confidence == "entropy"
    assert matches[0].severity is Severity.HIGH
    assert AWS_SECRET not in matches[0].redacted


@pytest.mark.parametrize(
    ("name", "value"),
    [
        ("LOG_LEVEL", "DEBUG"),
        ("AWS_REGION", "us-east-1"),
        ("DB_PASSWORD", "changeme"),
        ("API_KEY", "your-key-here"),
        ("SECRET", "${SECRET_FROM_SSM}"),
        ("TOKEN", "<replace-me>"),
        ("PASSWORD", "aaaaaaaaaaaaaaaa"),
        ("SECRET_ARN", "arn:aws:secretsmanager:us-east-1:111122223333:secret:db-AbCdEf"),
    ],
)
def test_placeholders_and_references_are_not_flagged(scanner, name, value):
    assert scanner.scan_env(name, value) == []


def test_plain_config_value_without_secret_name_is_not_flagged(scanner):
    # A high-entropy-ish value in a non-secret variable name is not assumed to be a secret.
    assert scanner.scan_env("BUILD_ID", "9f8e7d6c5b4a3210fedc") == []


def test_entropy_helpers():
    assert shannon_entropy("aaaa") == 0.0
    assert shannon_entropy("AKIA2E0A8F3B7C9D1E5F") > 3.0
    assert is_high_entropy("Q2m5nZ8vT1kLpR7wX3jH9cB4dF6gN0sA2eU5yI8o")
    assert not is_high_entropy("us-east-1")
    assert not is_high_entropy("short")


def test_redact_helper_is_irreversible():
    token = redact("AKIA2E0A8F3B7C9D1E5F")
    assert "AKIA2E0A8F3B7C9D1E5F" not in token
    assert token.startswith("AKI") and token.endswith(")")
