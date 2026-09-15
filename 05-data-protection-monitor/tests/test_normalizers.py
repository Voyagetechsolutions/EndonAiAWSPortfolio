from dataprotection_testkit import health_credentials_exposed_event, macie_event
from endon_core.findings import Domain, Severity
from endon_dataprotection.normalizers import normalize_event


def test_public_sensitive_data_is_critical_and_routable():
    event = macie_event("customer-exports", public=True, categories=["PERSONAL_INFORMATION"])

    [finding] = normalize_event(event)

    # This exact type is auto-remediated by the Project 1 s3-public-exposure playbook.
    assert finding.type == "DataProtection:S3/SensitiveDataPubliclyAccessible"
    assert finding.severity is Severity.CRITICAL
    assert finding.domain is Domain.DATA_PROTECTION
    assert finding.resources[0].details["bucketName"] == "customer-exports"


def test_non_public_sensitive_data_severity_from_categories():
    credentials = macie_event("secrets-dump", public=False, categories=["CREDENTIALS"])
    personal = macie_event("crm", public=False, categories=["PERSONAL_INFORMATION"])

    [cred_finding] = normalize_event(credentials)
    [personal_finding] = normalize_event(personal)

    assert cred_finding.type == "DataProtection:S3/SensitiveDataAtRest"
    assert cred_finding.severity is Severity.HIGH  # credentials
    assert personal_finding.severity is Severity.MEDIUM  # personal info


def test_health_credentials_exposed_is_critical():
    event = health_credentials_exposed_event("AKIA2E0A8F3B7C9D1E5F")

    [finding] = normalize_event(event)

    assert finding.type == "DataProtection:IAM/CredentialsExposed"
    assert finding.severity is Severity.CRITICAL
    assert finding.resources[0].details["accessKeyId"] == "AKIA2E0A8F3B7C9D1E5F"


def test_non_sensitive_and_unrelated_events_are_ignored():
    policy_macie = macie_event("b", public=False, categories=[])
    policy_macie["detail"]["type"] = "Policy:IAMUser/S3BlockPublicAccessDisabled"
    assert normalize_event(policy_macie) == []
    assert (
        normalize_event({"source": "aws.ec2", "detail-type": "EC2 State-change", "detail": {}})
        == []
    )
