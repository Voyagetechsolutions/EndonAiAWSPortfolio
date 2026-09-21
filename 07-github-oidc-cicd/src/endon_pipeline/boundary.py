"""The deploy role's blast radius: a narrow identity policy plus a permissions boundary.

Modern CDK deployments assume a set of bootstrap roles (``cdk-<qualifier>-deploy-role`` and
friends) that do the actual work. So the GitHub deploy role needs to do exactly one thing:
assume those bootstrap roles. Its identity policy grants only that.

A permissions boundary is the backstop. Even if the identity policy were ever widened (by
mistake or by a compromised pipeline that could edit it), the boundary caps what the role
can do — explicitly denying the privilege-escalation and destructive actions a compromised
CI job would reach for. The evaluator here reuses the Project 2 policy engine to prove the
combination.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from endon_iam_analyzer.policy import PermissionSet, PolicyDocument

CDK_BOOTSTRAP_ROLE_ARNS = ["arn:aws:iam::*:role/cdk-*"]

# Actions a compromised CI job would use to persist or escalate. The boundary denies them.
DENIED_ESCALATION_ACTIONS = [
    "iam:CreateUser",
    "iam:CreateAccessKey",
    "iam:CreateLoginProfile",
    "iam:UpdateLoginProfile",
    "iam:AttachUserPolicy",
    "iam:PutUserPolicy",
    "iam:AttachRolePolicy",
    "iam:PutRolePolicy",
    "iam:CreatePolicyVersion",
    "iam:DeleteRolePermissionsBoundary",
    "iam:PutRolePermissionsBoundary",
    "iam:PassRole",
    "organizations:*",
    "account:*",
]


def build_identity_policy(role_arns: list[str] = CDK_BOOTSTRAP_ROLE_ARNS) -> dict[str, Any]:
    """What the GitHub deploy role may do: assume the CDK bootstrap roles, nothing else."""
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AssumeCdkBootstrapRoles",
                "Effect": "Allow",
                "Action": "sts:AssumeRole",
                "Resource": role_arns,
            }
        ],
    }


def build_permissions_boundary() -> dict[str, Any]:
    """The cap on the deploy role: allow the deployment surface, deny escalation."""
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowDeploymentSurface",
                "Effect": "Allow",
                "Action": [
                    "sts:AssumeRole",
                    "sts:TagSession",
                    "cloudformation:*",
                    "s3:*",
                    "ssm:GetParameter*",
                    "ecr:*",
                ],
                "Resource": "*",
            },
            {
                "Sid": "DenyPrivilegeEscalationAndOrgChanges",
                "Effect": "Deny",
                "Action": DENIED_ESCALATION_ACTIONS,
                "Resource": "*",
            },
            {
                "Sid": "DenyLeavingOrDeletingCriticalData",
                "Effect": "Deny",
                "Action": ["s3:DeleteBucket", "dynamodb:DeleteTable", "kms:ScheduleKeyDeletion"],
                "Resource": "*",
            },
        ],
    }


@dataclass
class DeployRoleModel:
    """The deploy role's effective permissions: identity policy capped by the boundary."""

    identity: PermissionSet
    boundary: PermissionSet

    def can(self, action: str, resource: str = "*") -> bool:
        # A role with a boundary can do an action only if BOTH the identity policy and the
        # boundary allow it (and neither denies it) — exactly how IAM evaluates a boundary.
        return (
            self.identity.evaluate(action, resource).allowed
            and self.boundary.evaluate(action, resource).allowed
        )

    def boundary_denies(self, action: str, resource: str = "*") -> bool:
        return not self.boundary.evaluate(action, resource).allowed


def build_deploy_role_model(
    identity_policy: dict | None = None, boundary_policy: dict | None = None
) -> DeployRoleModel:
    identity = PolicyDocument.parse(identity_policy or build_identity_policy())
    boundary = PolicyDocument.parse(boundary_policy or build_permissions_boundary())
    return DeployRoleModel(
        identity=PermissionSet(identity.statements), boundary=PermissionSet(boundary.statements)
    )
