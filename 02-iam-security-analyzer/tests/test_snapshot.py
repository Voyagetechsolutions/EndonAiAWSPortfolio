"""The snapshot builder against a real (emulated) account: what boto3 actually returns."""

from endon_iam_analyzer.analyzer import IamAnalyzer
from endon_iam_analyzer.snapshot import build_snapshot


def test_snapshot_captures_principals_and_policy_documents(vulnerable_aws_account):
    snapshot = build_snapshot(vulnerable_aws_account, region="us-east-1")

    assert {"alice-admin", "bob-escalator", "dave-wildcard"} <= set(snapshot.users)
    assert "deployer-role" in snapshot.roles

    alice = snapshot.users["alice-admin"]
    assert snapshot.permissions_for(alice).grants_admin()

    # Managed policy documents were decoded (not left URL-encoded).
    wildcard = next(p for p in snapshot.policies.values() if p.name == "DeveloperWildcard")
    assert wildcard.document.statements[0].actions == ("s3:*",)

    deployer = snapshot.roles["deployer-role"]
    assert deployer.trust_policy is not None
    assert deployer.trust_policy.statements[0].matches_action("sts:assumerole")


def test_analysis_of_emulated_account_finds_real_issues(vulnerable_aws_account):
    snapshot = build_snapshot(vulnerable_aws_account, region="us-east-1")
    result = IamAnalyzer().analyze(snapshot)
    present = {f.type for f in result.findings}

    assert "IAM:User/AdministratorAccess" in present
    assert "IAM:Role/AdministratorAccess" in present
    assert "IAM:User/PrivilegeEscalation" in present
    assert "IAM:Role/TrustsExternalAccount" in present
    assert result.score < 100


def test_credential_report_is_parsed(vulnerable_aws_account):
    snapshot = build_snapshot(vulnerable_aws_account, region="us-east-1")
    alice = snapshot.users["alice-admin"]
    # moto populates the credential report; alice has one active access key.
    assert alice.credentials is not None
    assert alice.credentials.active_key_count >= 1
