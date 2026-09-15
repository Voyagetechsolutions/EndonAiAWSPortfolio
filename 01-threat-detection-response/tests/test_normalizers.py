from endon_core.events import DetailType, Source
from endon_core.findings import Severity
from endon_detection import samples
from endon_detection.normalizers import normalize_event

ACCOUNT, REGION = "111122223333", "eu-west-1"
INSTANCE = samples.instance_resource(
    "i-0abc123def4567890",
    vpc_id="vpc-0123",
    subnet_id="subnet-0123",
    network_interface_id="eni-0123",
    security_group_ids=["sg-0123"],
    iam_instance_profile_arn="arn:aws:iam::111122223333:instance-profile/web",
)


def security_hub_event(**finding_overrides):
    finding = {
        "Id": "arn:aws:securityhub:eu-west-1:111122223333:security-control/S3.8/finding/abc",
        "ProductArn": "arn:aws:securityhub:eu-west-1::product/aws/securityhub",
        "ProductName": "Security Hub",
        "AwsAccountId": ACCOUNT,
        "Region": REGION,
        "Title": "S3 general purpose buckets should block public access",
        "Severity": {"Label": "HIGH"},
        "Compliance": {"Status": "FAILED", "SecurityControlId": "S3.8"},
        "Workflow": {"Status": "NEW"},
        "RecordState": "ACTIVE",
        "Resources": [
            {"Type": "AwsS3Bucket", "Id": "arn:aws:s3:::customer-exports", "Region": REGION}
        ],
    }
    finding.update(finding_overrides)
    return {
        "source": "aws.securityhub",
        "detail-type": "Security Hub Findings - Imported",
        "detail": {"findings": [finding]},
    }


def test_guardduty_iam_user_finding():
    event = samples.api_calls_from_malicious_ip(ACCOUNT, REGION, "alice", "AKIAEXAMPLEKEY")

    [finding] = normalize_event(event)

    assert finding.id == event["detail"]["id"]
    assert finding.source == "aws.guardduty"
    assert finding.severity is Severity.MEDIUM
    assert [r.type for r in finding.resources] == ["AwsIamUser", "AwsIamAccessKey"]
    assert finding.resources[0].id == "arn:aws:iam::111122223333:user/alice"
    assert finding.tags["remoteIp"] == "198.51.100.23"
    assert finding.tags["api"] == "AuthorizeSecurityGroupIngress"
    assert finding.first_observed_at == event["detail"]["service"]["eventFirstSeen"]
    assert not finding.is_sample


def test_instance_credential_exfiltration_has_role_and_instance():
    event = samples.instance_credential_exfiltration(ACCOUNT, REGION, "web-app-role", INSTANCE)

    [finding] = normalize_event(event)

    role, instance = finding.resources
    assert role.type == "AwsIamRole" and role.details["roleName"] == "web-app-role"
    assert instance.type == "AwsEc2Instance"
    assert instance.details["instanceId"] == "i-0abc123def4567890"
    assert instance.details["vpcId"] == "vpc-0123"
    assert finding.severity is Severity.HIGH


def test_s3_finding_has_bucket_and_actor():
    event = samples.s3_block_public_access_disabled(
        ACCOUNT, REGION, "customer-exports", "alice", "AKIAEXAMPLEKEY"
    )

    [finding] = normalize_event(event)

    assert [r.type for r in finding.resources] == ["AwsIamUser", "AwsIamAccessKey", "AwsS3Bucket"]
    assert finding.resources_of("AwsS3Bucket")[0].details["bucketName"] == "customer-exports"


def test_archived_guardduty_findings_are_ignored():
    event = samples.port_probe(ACCOUNT, REGION, INSTANCE)
    event["detail"]["service"]["archived"] = True

    assert normalize_event(event) == []


def test_sample_findings_are_flagged():
    event = samples.guardduty_event(
        "Backdoor:EC2/C&CActivity.B",
        account_id=ACCOUNT,
        region=REGION,
        resource=INSTANCE,
        severity=8.0,
        title="sample",
        sample=True,
    )

    [finding] = normalize_event(event)

    assert finding.is_sample


def test_security_hub_control_finding():
    [finding] = normalize_event(security_hub_event())

    assert finding.type == "SecurityHub:S3.8"
    assert finding.severity is Severity.HIGH
    assert finding.resources[0].name == "customer-exports"


def test_security_hub_copies_of_guardduty_findings_are_skipped():
    assert normalize_event(security_hub_event(ProductName="GuardDuty")) == []


def test_custom_security_hub_findings_are_not_trusted():
    custom = "arn:aws:securityhub:eu-west-1:111122223333:product/111122223333/default"
    assert normalize_event(security_hub_event(ProductArn=custom, ProductName="Default")) == []


def test_resolved_or_passed_security_hub_findings_are_skipped():
    assert normalize_event(security_hub_event(Workflow={"Status": "RESOLVED"})) == []
    assert (
        normalize_event(
            security_hub_event(Compliance={"Status": "PASSED", "SecurityControlId": "S3.8"})
        )
        == []
    )


def test_endon_finding_source_is_taken_from_the_event_envelope():
    [guardduty] = normalize_event(
        samples.api_calls_from_malicious_ip(ACCOUNT, REGION, "alice", "AKIAEXAMPLEKEY")
    )
    forged = {
        "source": Source.POSTURE_SCANNER,
        "detail-type": DetailType.FINDING,
        "detail": {"finding": guardduty.to_dict()},
    }

    [finding] = normalize_event(forged)

    assert finding.source == Source.POSTURE_SCANNER


def test_events_from_unknown_publishers_are_ignored():
    event = {
        "source": "endon.unknown",
        "detail-type": DetailType.FINDING,
        "detail": {"finding": {}},
    }
    assert normalize_event(event) == []
