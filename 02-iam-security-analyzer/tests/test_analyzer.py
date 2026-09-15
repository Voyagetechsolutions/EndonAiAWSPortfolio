import pytest

from endon_core.findings import Severity
from endon_iam_analyzer.analyzer import IamAnalyzer
from iam_testkit import NOW, vulnerable_snapshot


@pytest.fixture(scope="module")
def result():
    return IamAnalyzer().analyze(vulnerable_snapshot(), now=NOW)


def types_for(result, principal_substring):
    return {
        f.type for f in result.findings if any(principal_substring in r.id for r in f.resources)
    }


def find(result, finding_type, principal_substring):
    return next(
        (
            f
            for f in result.findings
            if f.type == finding_type and any(principal_substring in r.id for r in f.resources)
        ),
        None,
    )


def test_every_planted_issue_is_found(result):
    present = {f.type for f in result.findings}
    expected = {
        "IAM:User/AdministratorAccess",
        "IAM:Role/AdministratorAccess",
        "IAM:User/PrivilegeEscalation",
        "IAM:Role/PrivilegeEscalation",
        "IAM:Policy/WildcardAction",
        "IAM:Policy/NotActionWithAllow",
        "IAM:Role/TrustsExternalAccount",
        "IAM:Role/TrustsAnyPrincipal",
        "IAM:User/MissingMfa",
        "IAM:User/MultipleActiveKeys",
        "IAM:AccessKey/Stale",
        "IAM:AccessKey/Unused",
        "IAM:Root/AccessKeyActive",
        "IAM:Root/MfaDisabled",
    }
    assert expected <= present, f"missing: {expected - present}"


def test_admin_user_and_role(result):
    assert find(result, "IAM:User/AdministratorAccess", "alice-admin").severity is Severity.CRITICAL
    assert (
        find(result, "IAM:Role/AdministratorAccess", "deployer-role").severity is Severity.CRITICAL
    )


def test_direct_escalation_users(result):
    bob = find(result, "IAM:User/PrivilegeEscalation", "bob-escalator")
    assert bob.severity is Severity.CRITICAL
    assert "AttachUserPolicy" in bob.tags["directTechniques"]

    carol = find(result, "IAM:User/PrivilegeEscalation", "carol-passrole")
    assert "PassRoleToLambda" in carol.tags["directTechniques"]
    assert carol.severity is Severity.HIGH


def test_transitive_escalation_via_role(result):
    mallory = find(result, "IAM:User/PrivilegeEscalation", "mallory")
    assert mallory is not None
    assert "escalation-target-role" in mallory.tags["viaRoles"]


def test_break_glass_admin_is_downgraded_not_hidden(result):
    finding = find(result, "IAM:User/AdministratorAccess", "break-glass")
    assert finding is not None
    assert finding.severity is Severity.HIGH  # one level below CRITICAL
    assert "protected" in finding.title


def test_service_linked_role_is_ignored(result):
    assert types_for(result, "AWSServiceRoleForAutoScaling") == set()


def test_correctly_configured_resources_produce_no_findings(result):
    # A scoped read-only user, an ExternalId-gated partner role, and a scoped policy.
    assert types_for(result, "erin-readonly") == set()
    assert types_for(result, "partner-role") == set()
    assert not any("ScopedS3Reader" in r.id for f in result.findings for r in f.resources)


def test_external_trust_only_flagged_without_external_id(result):
    assert find(result, "IAM:Role/TrustsExternalAccount", "deployer-role") is not None
    assert find(result, "IAM:Role/TrustsExternalAccount", "partner-role") is None


def test_wildcard_and_notaction(result):
    assert find(result, "IAM:Policy/WildcardAction", "DeveloperWildcard") is not None
    dave = find(result, "IAM:Policy/WildcardAction", "dave-wildcard")  # inline iam:*
    assert dave.severity is Severity.HIGH
    assert find(result, "IAM:Policy/NotActionWithAllow", "NotActionAdmin") is not None


def test_score_reflects_severity(result):
    assert 0 <= result.score < 40  # a badly misconfigured account scores low
    assert result.counts["CRITICAL"] >= 4


def test_findings_are_deduplicated_and_have_stable_ids(result):
    ids = [f.id for f in result.findings]
    assert len(ids) == len(set(ids))

    again = IamAnalyzer().analyze(vulnerable_snapshot(), now=NOW)
    assert {f.id for f in again.findings} == set(ids)
