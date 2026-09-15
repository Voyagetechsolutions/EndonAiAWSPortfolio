"""The forensics engine must preserve evidence — never destroy the host, volumes or evidence."""

import json

import pytest

pytest.importorskip("aws_cdk")

from aws_cdk import App, Environment  # noqa: E402
from aws_cdk.assertions import Template  # noqa: E402

from endon_forensics import rules  # noqa: E402
from forensics_stack import ForensicsStack  # noqa: E402
from platform_stack import PlatformStack  # noqa: E402

# EC2 actions the forensics role is allowed. Everything else on ec2 is forbidden.
ALLOWED_EC2 = {
    "ec2:DescribeInstances",
    "ec2:DescribeInstanceAttribute",
    "ec2:DescribeVolumes",
    "ec2:DescribeSnapshots",
    "ec2:DescribeSecurityGroups",
    "ec2:GetConsoleOutput",
    "ec2:GetConsoleScreenshot",
    "ec2:CreateSnapshot",
    "ec2:CreateSnapshots",
    "ec2:CreateTags",
}
DESTRUCTIVE = {
    "ec2:TerminateInstances",
    "ec2:StopInstances",
    "ec2:DeleteSnapshot",
    "ec2:DeleteVolume",
}


@pytest.fixture(scope="module")
def template():
    app = App()
    env = Environment(account="111111111111", region="us-east-1")
    platform = PlatformStack(app, "EndonPlatform", env=env)
    forensics = ForensicsStack(app, "EndonForensics", platform=platform, env=env)
    return Template.from_stack(forensics)


def as_list(value):
    return value if isinstance(value, list) else [value]


def statements(template):
    for policy in template.find_resources("AWS::IAM::Policy").values():
        yield from policy["Properties"]["PolicyDocument"]["Statement"]


def test_forensics_role_has_no_destructive_ec2_permissions(template):
    for statement in statements(template):
        if statement["Effect"] != "Allow":
            continue
        for action in as_list(statement["Action"]):
            if action.startswith("ec2:"):
                assert action in ALLOWED_EC2, f"unexpected EC2 permission granted: {action}"


def test_destructive_actions_are_explicitly_denied(template):
    denies = [s for s in statements(template) if s["Effect"] == "Deny"]
    denied_actions = {a for s in denies for a in as_list(s["Action"])}
    assert denied_actions >= DESTRUCTIVE
    assert "s3:BypassGovernanceRetention" in denied_actions  # cannot delete Object Lock evidence


def test_subscribed_to_the_forensics_request_event(template):
    template.resource_count_is("AWS::Events::Rule", 1)
    deployed = {
        json.dumps(rule["Properties"]["EventPattern"], sort_keys=True)
        for rule in template.find_resources("AWS::Events::Rule").values()
    }
    assert json.dumps(rules.FORENSICS_REQUESTED, sort_keys=True) in deployed


def test_failures_raise_alarms(template):
    template.resource_count_is("AWS::CloudWatch::Alarm", 2)


def test_is_python_and_traced(template):
    template.has_resource_properties(
        "AWS::Lambda::Function",
        {
            "Handler": "endon_forensics.handler.lambda_handler",
            "Runtime": "python3.13",
            "TracingConfig": {"Mode": "Active"},
        },
    )
