"""Synthesizes the CDK app and verifies the security properties the design relies on."""

import json

import pytest

pytest.importorskip("aws_cdk")

from aws_cdk import App, Environment  # noqa: E402
from aws_cdk.assertions import Match, Template  # noqa: E402

from detection_stack import DetectionResponseStack  # noqa: E402
from endon_detection import rules  # noqa: E402
from platform_stack import PlatformStack  # noqa: E402

READ_ONLY_PREFIXES = ("Describe", "List", "Get")
WILDCARD_WRITE_ALLOWED = {"xray:PutTraceSegments", "xray:PutTelemetryRecords"}


@pytest.fixture(scope="module")
def templates():
    app = App()
    env = Environment(account="111111111111", region="us-east-1")
    platform = PlatformStack(app, "EndonPlatform", env=env)
    detection = DetectionResponseStack(app, "EndonDetectionResponse", platform=platform, env=env)
    return Template.from_stack(platform), Template.from_stack(detection)


def as_list(value):
    return value if isinstance(value, list) else [value]


def policy_statements(template):
    for policy in template.find_resources("AWS::IAM::Policy").values():
        yield from policy["Properties"]["PolicyDocument"]["Statement"]


def test_response_engine_is_deployed_in_dry_run_by_default(templates):
    _, detection = templates
    detection.has_resource_properties(
        "AWS::Lambda::Function",
        {
            "Handler": "endon_detection.handler.lambda_handler",
            "Runtime": "python3.13",
            "TracingConfig": {"Mode": "Active"},
            "Environment": {"Variables": Match.object_like({"ENDON_RESPONSE_MODE": "dry_run"})},
        },
    )


def test_deployed_event_patterns_are_the_tested_patterns(templates):
    _, detection = templates
    deployed = {
        json.dumps(rule["Properties"]["EventPattern"], sort_keys=True)
        for rule in detection.find_resources("AWS::Events::Rule").values()
    }
    for pattern in (rules.GUARDDUTY_FINDINGS, rules.SECURITY_HUB_FINDINGS, rules.ENDON_FINDINGS):
        assert json.dumps(pattern, sort_keys=True) in deployed


def test_wildcard_resources_are_only_granted_read_only_actions(templates):
    _, detection = templates
    for statement in policy_statements(detection):
        if statement["Effect"] != "Allow" or "*" not in as_list(statement["Resource"]):
            continue
        for action in as_list(statement["Action"]):
            assert action in WILDCARD_WRITE_ALLOWED or action.split(":")[1].startswith(
                READ_ONLY_PREFIXES
            ), action


def test_responder_cannot_modify_its_own_role(templates):
    _, detection = templates
    denies = [s for s in policy_statements(detection) if s["Effect"] == "Deny"]
    self_modification = [
        s
        for s in denies
        if "iam:PutRolePolicy" in as_list(s["Action"])
        and "iam:AttachRolePolicy" in as_list(s["Action"])
    ]
    assert self_modification, "expected an explicit deny on the responder's own role"


def test_responder_failures_raise_alarms(templates):
    _, detection = templates
    detection.resource_count_is("AWS::CloudWatch::Alarm", 2)


def test_platform_data_is_encrypted_and_retained(templates):
    platform, _ = templates
    platform.has_resource_properties("AWS::KMS::Key", {"EnableKeyRotation": True})
    platform.has_resource(
        "AWS::DynamoDB::Table",
        {
            "DeletionPolicy": "Retain",
            "Properties": Match.object_like(
                {
                    "SSESpecification": Match.object_like({"SSEEnabled": True, "SSEType": "KMS"}),
                    "PointInTimeRecoverySpecification": {"PointInTimeRecoveryEnabled": True},
                    "DeletionProtectionEnabled": True,
                }
            ),
        },
    )
    platform.has_resource_properties("AWS::SNS::Topic", {"KmsMasterKeyId": Match.any_value()})


def test_evidence_bucket_is_immutable_and_private(templates):
    platform, _ = templates
    platform.has_resource_properties(
        "AWS::S3::Bucket",
        {
            "ObjectLockEnabled": True,
            "ObjectLockConfiguration": {
                "ObjectLockEnabled": "Enabled",
                "Rule": {"DefaultRetention": {"Mode": "GOVERNANCE", "Days": 90}},
            },
            "VersioningConfiguration": {"Status": "Enabled"},
            "PublicAccessBlockConfiguration": {
                "BlockPublicAcls": True,
                "BlockPublicPolicy": True,
                "IgnorePublicAcls": True,
                "RestrictPublicBuckets": True,
            },
        },
    )


def test_unknown_response_mode_is_rejected():
    with pytest.raises(ValueError, match="response_mode"):
        DetectionResponseStack(App(), "Invalid", platform=None, response_mode="enabled")
