import json

from dataprotection_testkit import RAW_SECRETS, REGION, build_leaky_account
from endon_dataprotection.scanner import DataProtectionScanner


def scan(aws):
    build_leaky_account(aws)
    return DataProtectionScanner().scan_account(aws, region=REGION)


def test_finds_secrets_across_services(aws):
    result = scan(aws)
    present = {f.type for f in result.findings}
    assert "DataProtection:Lambda/SecretInEnvironment" in present
    assert "DataProtection:EC2/SecretInUserData" in present
    assert "DataProtection:SecretsManager/RotationDisabled" in present
    assert result.errors == []
    assert result.score < 100


def test_no_raw_secret_ever_appears_in_a_finding(aws):
    result = scan(aws)
    blob = json.dumps(result.to_dict())
    for secret in RAW_SECRETS:
        assert secret not in blob, f"raw secret leaked into findings: {secret[:6]}…"


def test_clean_resources_are_not_flagged(aws):
    result = scan(aws)
    flagged = {r.id for f in result.findings for r in f.resources}
    assert not any("healthcheck" in fid for fid in flagged)  # the clean lambda
    # The leaky lambda IS flagged, and its finding names the redacted secrets, not plaintext.
    leaky = next(
        f for f in result.findings if f.type == "DataProtection:Lambda/SecretInEnvironment"
    )
    assert "sha256:" in leaky.description
    assert "changeme" not in leaky.description  # the placeholder env var was suppressed


def test_lambda_finding_severity_reflects_worst_secret(aws):
    result = scan(aws)
    leaky = next(
        f for f in result.findings if f.type == "DataProtection:Lambda/SecretInEnvironment"
    )
    assert leaky.severity.value in ("HIGH", "CRITICAL")
    assert int(leaky.tags["secretCount"]) >= 2  # db url + github token
