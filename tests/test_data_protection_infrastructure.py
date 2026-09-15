"""The data-protection monitor reads to detect, and must never read a secret's value."""

import json

import pytest

pytest.importorskip("aws_cdk")

from aws_cdk import App, Environment  # noqa: E402
from aws_cdk.assertions import Template  # noqa: E402

from data_protection_stack import DataProtectionStack  # noqa: E402
from endon_dataprotection import rules  # noqa: E402
from platform_stack import PlatformStack  # noqa: E402

READ_ONLY_VERBS = ("describe", "list", "get")
# Reading a secret's *value* would make the monitor a secret-exfiltration path.
FORBIDDEN = {"secretsmanager:GetSecretValue", "secretsmanager:BatchGetSecretValue"}


@pytest.fixture(scope="module")
def template():
    app = App()
    env = Environment(account="111111111111", region="us-east-1")
    platform = PlatformStack(app, "EndonPlatform", env=env)
    stack = DataProtectionStack(app, "EndonDataProtection", platform=platform, env=env)
    return Template.from_stack(stack)


def as_list(value):
    return value if isinstance(value, list) else [value]


def statements(template):
    for policy in template.find_resources("AWS::IAM::Policy").values():
        yield from policy["Properties"]["PolicyDocument"]["Statement"]


def test_inspection_permissions_are_read_only(template):
    audited = {"lambda", "ec2", "secretsmanager", "macie2"}
    for statement in statements(template):
        if statement["Effect"] != "Allow" or "*" not in as_list(statement.get("Resource")):
            continue
        for action in as_list(statement["Action"]):
            service, _, verb = action.partition(":")
            if service in audited:
                assert verb.lower().startswith(READ_ONLY_VERBS), f"non-read action: {action}"


def test_never_reads_secret_values(template):
    granted = {
        a for s in statements(template) if s["Effect"] == "Allow" for a in as_list(s["Action"])
    }
    assert not (granted & FORBIDDEN), "the monitor must never read secret plaintext"


def test_consumes_macie_and_health_events(template):
    deployed = {
        json.dumps(rule["Properties"].get("EventPattern"), sort_keys=True)
        for rule in template.find_resources("AWS::Events::Rule").values()
    }
    assert json.dumps(rules.MACIE_FINDINGS, sort_keys=True) in deployed
    assert json.dumps(rules.HEALTH_CREDENTIALS_EXPOSED, sort_keys=True) in deployed


def test_two_functions_and_alarms(template):
    template.resource_count_is("AWS::Lambda::Function", 2)
    template.resource_count_is("AWS::CloudWatch::Alarm", 2)
    for handler in (
        "endon_dataprotection.handler.event_handler",
        "endon_dataprotection.handler.scan_handler",
    ):
        template.has_resource_properties(
            "AWS::Lambda::Function", {"Handler": handler, "Runtime": "python3.13"}
        )
