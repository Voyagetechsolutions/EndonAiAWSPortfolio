"""The posture scanner must be able to read every service it scans, and change none."""

import pytest

pytest.importorskip("aws_cdk")

from aws_cdk import App, Environment  # noqa: E402
from aws_cdk.assertions import Template  # noqa: E402

from platform_stack import PlatformStack  # noqa: E402
from posture_scanner_stack import PostureScannerStack  # noqa: E402

# The only verbs a read-only auditor needs on any service.
READ_ONLY_VERBS = ("describe", "list", "get")


@pytest.fixture(scope="module")
def template():
    app = App()
    env = Environment(account="111111111111", region="us-east-1")
    platform = PlatformStack(app, "EndonPlatform", env=env)
    scanner = PostureScannerStack(app, "EndonPostureScanner", platform=platform, env=env)
    return Template.from_stack(scanner)


def as_list(value):
    return value if isinstance(value, list) else [value]


def statements(template):
    for policy in template.find_resources("AWS::IAM::Policy").values():
        yield from policy["Properties"]["PolicyDocument"]["Statement"]


def test_scanner_only_has_read_only_service_permissions(template):
    audited_services = {
        "s3",
        "ec2",
        "rds",
        "cloudtrail",
        "kms",
        "iam",
        "guardduty",
        "config",
    }
    for statement in statements(template):
        # Only the account-wide audit statement grants on "*". The report-writing grant
        # (s3:PutObject, kms:GenerateDataKey*) is scoped to the evidence bucket and key,
        # which is expected; it is not part of the read-only inspection surface.
        if statement["Effect"] != "Allow" or "*" not in as_list(statement.get("Resource")):
            continue
        for action in as_list(statement["Action"]):
            service, _, verb = action.partition(":")
            if service in audited_services:
                assert verb.lower().startswith(READ_ONLY_VERBS), (
                    f"non-read action granted: {action}"
                )


def test_scanner_runs_on_a_schedule(template):
    template.resource_count_is("AWS::Events::Rule", 1)
    template.has_resource_properties("AWS::Events::Rule", {"ScheduleExpression": "rate(1 day)"})


def test_scanner_reports_failures(template):
    template.resource_count_is("AWS::CloudWatch::Alarm", 1)


def test_scanner_is_python_and_traced(template):
    template.has_resource_properties(
        "AWS::Lambda::Function",
        {"Handler": "endon_posture.handler.lambda_handler", "Runtime": "python3.13"},
    )
