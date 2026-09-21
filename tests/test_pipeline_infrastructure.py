"""The CI/CD stack: an OIDC-trusted deploy role scoped by a permissions boundary."""

import pytest

pytest.importorskip("aws_cdk")

from aws_cdk import App, Environment  # noqa: E402
from aws_cdk.assertions import Match, Template  # noqa: E402

from pipeline_stack import PipelineStack  # noqa: E402


@pytest.fixture(scope="module")
def template():
    app = App()
    stack = PipelineStack(
        app,
        "EndonPipeline",
        github_owner="Voyagetechsolutions",
        github_repo="EndonAiAWSPortfolio",
        env=Environment(account="111111111111", region="us-east-1"),
    )
    return Template.from_stack(stack)


def as_list(value):
    return value if isinstance(value, list) else [value]


def deploy_role(template):
    """The deploy role is the one trusted through web identity.

    The OIDC provider is a CDK custom resource, so the synth also emits a Lambda service
    role; select by the trust action so we never assert against that one by accident.
    """
    for role in template.find_resources("AWS::IAM::Role").values():
        statements = role["Properties"]["AssumeRolePolicyDocument"]["Statement"]
        if any(s.get("Action") == "sts:AssumeRoleWithWebIdentity" for s in statements):
            return role
    raise AssertionError("no web-identity deploy role found")


def test_creates_a_github_oidc_provider(template):
    template.has_resource_properties(
        "Custom::AWSCDKOpenIdConnectProvider",
        {
            "Url": "https://token.actions.githubusercontent.com",
            "ClientIDList": ["sts.amazonaws.com"],
        },
    )


def test_deploy_role_trusts_only_via_web_identity_with_conditions(template):
    role = deploy_role(template)
    statement = role["Properties"]["AssumeRolePolicyDocument"]["Statement"][0]
    assert statement["Action"] == "sts:AssumeRoleWithWebIdentity"
    condition = statement["Condition"]
    assert (
        condition["StringEquals"]["token.actions.githubusercontent.com:aud"] == "sts.amazonaws.com"
    )
    subs = condition["StringLike"]["token.actions.githubusercontent.com:sub"]
    assert any(
        "Voyagetechsolutions/EndonAiAWSPortfolio:ref:refs/heads/main" in s for s in as_list(subs)
    )


def test_deploy_role_has_a_permissions_boundary(template):
    template.has_resource_properties("AWS::IAM::Role", {"PermissionsBoundary": Match.any_value()})


def test_boundary_denies_escalation_and_data_destruction(template):
    policies = template.find_resources("AWS::IAM::ManagedPolicy")
    statements = [
        s for p in policies.values() for s in p["Properties"]["PolicyDocument"]["Statement"]
    ]
    denied = {a for s in statements if s["Effect"] == "Deny" for a in as_list(s["Action"])}
    assert {"iam:CreateUser", "iam:AttachUserPolicy", "iam:PassRole"} <= denied
    assert {"s3:DeleteBucket"} <= denied


def test_deploy_role_can_only_assume_cdk_roles(template):
    role = deploy_role(template)
    inline = role["Properties"].get("Policies", [])
    actions = {
        a
        for policy in inline
        for s in policy["PolicyDocument"]["Statement"]
        for a in as_list(s["Action"])
    }
    # The only thing its identity policy grants is assuming roles (the CDK bootstrap roles).
    assert actions <= {"sts:AssumeRole"}
