"""The blast-radius proof: what a (compromised) deploy role can and cannot do."""

from endon_iam_analyzer.policy import PermissionSet, PolicyDocument
from endon_pipeline.boundary import build_deploy_role_model, build_permissions_boundary


def test_deploy_role_can_assume_cdk_roles_and_nothing_else():
    model = build_deploy_role_model()
    assert model.can(
        "sts:AssumeRole", "arn:aws:iam::123456789012:role/cdk-hnb659fds-deploy-role-123-us-east-1"
    )
    # It cannot do anything else directly — its identity policy grants only the assume.
    assert not model.can("s3:GetObject")
    assert not model.can("cloudformation:CreateStack")


def test_boundary_denies_privilege_escalation():
    model = build_deploy_role_model()
    for action in (
        "iam:CreateUser",
        "iam:CreateAccessKey",
        "iam:AttachUserPolicy",
        "iam:PutUserPolicy",
        "iam:CreateLoginProfile",
        "iam:PassRole",
        "organizations:LeaveOrganization",
    ):
        assert model.boundary_denies(action), f"boundary should deny {action}"


def test_boundary_denies_destructive_data_actions():
    model = build_deploy_role_model()
    for action in ("s3:DeleteBucket", "dynamodb:DeleteTable", "kms:ScheduleKeyDeletion"):
        assert model.boundary_denies(action)


def test_boundary_is_the_backstop_even_if_identity_is_widened():
    # Suppose a compromised pipeline widened the identity policy to Administrator.
    admin_identity = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}],
    }
    model = build_deploy_role_model(identity_policy=admin_identity)
    # The boundary still caps the role: escalation stays denied.
    assert not model.can("iam:CreateUser")
    assert not model.can("s3:DeleteBucket")
    # But it can still perform the legitimate deployment surface.
    assert model.can("cloudformation:CreateStack")


def test_boundary_allows_the_deployment_surface():
    boundary = PermissionSet(PolicyDocument.parse(build_permissions_boundary()).statements)
    for action in ("cloudformation:CreateStack", "s3:PutObject", "sts:AssumeRole", "ecr:PutImage"):
        assert boundary.evaluate(action).allowed
