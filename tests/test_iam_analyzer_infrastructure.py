"""The IAM analyzer must be able to read IAM but never change it."""

import pytest

pytest.importorskip("aws_cdk")

from aws_cdk import App, Environment  # noqa: E402
from aws_cdk.assertions import Template  # noqa: E402

from iam_analyzer_stack import IamAnalyzerStack  # noqa: E402
from platform_stack import PlatformStack  # noqa: E402

# The only verbs an inspection tool needs. Anything else on the iam: service is a write.
READ_ONLY_IAM_VERBS = ("get", "list", "generate", "simulate")


@pytest.fixture(scope="module")
def template():
    app = App()
    env = Environment(account="111111111111", region="us-east-1")
    platform = PlatformStack(app, "EndonPlatform", env=env)
    analyzer = IamAnalyzerStack(app, "EndonIamAnalyzer", platform=platform, env=env)
    return Template.from_stack(analyzer)


def as_list(value):
    return value if isinstance(value, list) else [value]


def statements(template):
    for policy in template.find_resources("AWS::IAM::Policy").values():
        yield from policy["Properties"]["PolicyDocument"]["Statement"]


def test_analyzer_never_has_iam_write_permissions(template):
    for statement in statements(template):
        if statement["Effect"] != "Allow":
            continue
        for action in as_list(statement["Action"]):
            service, _, verb = action.partition(":")
            if service == "iam":
                assert verb.lower().startswith(READ_ONLY_IAM_VERBS), f"IAM write granted: {action}"


def test_analyzer_runs_on_a_schedule(template):
    template.resource_count_is("AWS::Events::Rule", 1)
    # CDK normalizes rate(24 hours) to the equivalent rate(1 day).
    template.has_resource_properties("AWS::Events::Rule", {"ScheduleExpression": "rate(1 day)"})


def test_analyzer_reports_failures(template):
    template.resource_count_is("AWS::CloudWatch::Alarm", 1)


def test_analyzer_is_python_and_traced(template):
    template.has_resource_properties(
        "AWS::Lambda::Function",
        {"Handler": "endon_iam_analyzer.handler.lambda_handler", "Runtime": "python3.13"},
    )
