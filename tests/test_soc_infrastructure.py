"""The SOC reads to display, and must never be able to write platform state or serve unauthenticated."""

import pytest

pytest.importorskip("aws_cdk")

from aws_cdk import App, Environment  # noqa: E402
from aws_cdk.assertions import Template  # noqa: E402

from platform_stack import PlatformStack  # noqa: E402
from soc_stack import SocStack  # noqa: E402

# Any of these on the incident/finding tables would turn the read-only console into a writer.
FORBIDDEN_DYNAMO_WRITES = {
    "dynamodb:PutItem",
    "dynamodb:UpdateItem",
    "dynamodb:DeleteItem",
    "dynamodb:BatchWriteItem",
}
HEALTH_SERVICES = {"guardduty", "securityhub", "cloudtrail", "config"}
READ_ONLY_VERBS = ("describe", "list", "get", "batchget")


@pytest.fixture(scope="module")
def template():
    app = App()
    env = Environment(account="111111111111", region="us-east-1")
    platform = PlatformStack(app, "EndonPlatform", env=env)
    stack = SocStack(app, "EndonSoc", platform=platform, env=env)
    return Template.from_stack(stack)


def as_list(value):
    return value if isinstance(value, list) else [value]


def statements(template):
    for policy in template.find_resources("AWS::IAM::Policy").values():
        yield from policy["Properties"]["PolicyDocument"]["Statement"]


def granted_actions(template):
    return {
        a
        for s in statements(template)
        if s["Effect"] == "Allow"
        for a in as_list(s.get("Action", []))
    }


def test_console_cannot_write_the_platform_tables(template):
    assert not (granted_actions(template) & FORBIDDEN_DYNAMO_WRITES)


def test_detective_health_permissions_are_read_only(template):
    for action in granted_actions(template):
        service, _, verb = action.partition(":")
        if service in HEALTH_SERVICES:
            assert verb.lower().startswith(READ_ONLY_VERBS), f"non-read action: {action}"


def test_every_api_route_is_cognito_authenticated(template):
    methods = template.find_resources("AWS::ApiGateway::Method")
    assert methods, "the API exposes no methods"
    for method in methods.values():
        assert method["Properties"]["AuthorizationType"] == "COGNITO_USER_POOLS"


def test_a_cognito_user_pool_gates_access(template):
    template.resource_count_is("AWS::Cognito::UserPool", 1)
    # Operators are invited, never self-registered.
    template.has_resource_properties(
        "AWS::Cognito::UserPool", {"AdminCreateUserConfig": {"AllowAdminCreateUserOnly": True}}
    )


def test_one_read_only_lambda_behind_the_api(template):
    template.resource_count_is("AWS::Lambda::Function", 1)
    template.has_resource_properties(
        "AWS::Lambda::Function",
        {"Handler": "endon_soc.lambda_handler.handler", "Runtime": "python3.13"},
    )
