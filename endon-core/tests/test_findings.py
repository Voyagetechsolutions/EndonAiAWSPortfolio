import pytest

from endon_core.findings import Domain, Finding, Resource, Severity
from endon_core.incidents import ActionKind, ActionRecord, ActionStatus, Incident, IncidentStatus


def make_finding(**overrides) -> Finding:
    values = {
        "source": "endon.posture-scanner",
        "type": "Posture:S3/BucketPubliclyAccessible",
        "title": "Bucket is publicly accessible",
        "severity": Severity.HIGH,
        "account_id": "111122223333",
        "region": "eu-west-1",
        "resources": [Resource("AwsS3Bucket", "arn:aws:s3:::customer-exports")],
        "control_id": "S3-001",
        "domain": Domain.DATA_PROTECTION,
        "remediation": "Enable S3 Block Public Access.",
    }
    values.update(overrides)
    return Finding(**values)


@pytest.mark.parametrize(
    ("score", "expected"),
    [
        (0.0, "INFORMATIONAL"),
        (2.0, "LOW"),
        (3.9, "LOW"),
        (4.0, "MEDIUM"),
        (7.0, "HIGH"),
        (8.9, "HIGH"),
        (9.0, "CRITICAL"),
    ],
)
def test_guardduty_severity_mapping(score, expected):
    assert Severity.from_guardduty(score) == Severity(expected)


def test_severity_comparison_uses_rank_not_alphabetical_order():
    assert Severity.CRITICAL.at_least(Severity.HIGH)
    assert Severity.MEDIUM.at_least(Severity.LOW)
    assert not Severity.LOW.at_least(Severity.MEDIUM)  # "LOW" > "MEDIUM" alphabetically


def test_fingerprint_is_stable_and_resource_order_independent():
    a = Resource("AwsIamUser", "arn:aws:iam::111122223333:user/a")
    b = Resource("AwsIamUser", "arn:aws:iam::111122223333:user/b")
    assert make_finding(resources=[a, b]).id == make_finding(resources=[b, a]).id
    assert make_finding(resources=[a]).id != make_finding(resources=[b]).id


def test_round_trip_through_dict():
    finding = make_finding(tags={"sample": "true"}, raw={"original": 1})
    restored = Finding.from_dict(finding.to_dict())
    assert restored == finding
    assert restored.is_sample
    assert "raw" not in finding.to_dict(include_raw=False)


def test_resource_name_from_arn():
    assert Resource("AwsS3Bucket", "arn:aws:s3:::customer-exports").name == "customer-exports"
    assert Resource("AwsIamUser", "arn:aws:iam::1:user/ops/alice").name == "alice"
    assert Resource("AwsEc2Instance", "arn:aws:ec2:us-east-1:1:instance/i-0abc").name == "i-0abc"


def test_asff_rendering():
    finding = make_finding()
    record = finding.to_asff(
        "arn:aws:securityhub:eu-west-1:111122223333:product/111122223333/default"
    )
    assert record["SchemaVersion"] == "2018-10-08"
    assert record["Types"] == [
        "Software and Configuration Checks/Endon AI/Posture:S3/BucketPubliclyAccessible"
    ]
    assert record["Severity"] == {"Label": "HIGH"}
    assert record["GeneratorId"] == "S3-001"
    assert record["Resources"][0] == {
        "Type": "AwsS3Bucket",
        "Id": "arn:aws:s3:::customer-exports",
        "Region": "eu-west-1",
    }
    assert record["Remediation"]["Recommendation"]["Text"] == "Enable S3 Block Public Access."
    assert record["ProductFields"]["endon/source"] == "endon.posture-scanner"


def test_incident_round_trip_and_time_to_contain():
    finding = make_finding(first_observed_at="2026-09-15T09:31:04.000Z")
    incident = Incident.open(finding, "s3-public-exposure", opened_at="2026-09-15T09:31:05.000Z")
    incident.actions.append(
        ActionRecord(
            "block_s3_public_access",
            ActionKind.REMEDIATE,
            finding.resources[0].id,
            ActionStatus.SUCCEEDED,
        )
    )
    incident.log("Incident opened")
    incident.status = IncidentStatus.CONTAINED
    incident.contained_at = "2026-09-15T09:31:09.500Z"

    assert incident.incident_id == Incident.id_for(finding)
    assert incident.time_to_contain_seconds == 5.5
    restored = Incident.from_dict(incident.to_dict())
    assert restored == incident
