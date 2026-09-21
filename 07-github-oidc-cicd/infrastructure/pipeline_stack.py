"""Deploys the keyless CI/CD trust: a GitHub OIDC provider and a scoped deploy role.

The deploy role trusts GitHub's OIDC provider, but only for the exact repository and branch
(the trust conditions are the ones the simulator proves). Its identity policy lets it assume
only the CDK bootstrap roles, and a customer-managed permissions boundary caps it so a
compromised pipeline cannot escalate privilege or destroy data.
"""

from __future__ import annotations

from typing import Any

from aws_cdk import CfnOutput, Stack
from aws_cdk import aws_iam as iam
from constructs import Construct

from endon_pipeline.boundary import build_identity_policy, build_permissions_boundary
from endon_pipeline.oidc import DEFAULT_AUDIENCE, OIDC_PROVIDER_DOMAIN, GitHubOidcConfig


class PipelineStack(Stack):
    def __init__(
        self,
        scope: Construct,
        construct_id: str,
        *,
        github_owner: str,
        github_repo: str,
        deploy_branches: tuple[str, ...] = ("main",),
        **kwargs: Any,
    ) -> None:
        super().__init__(scope, construct_id, **kwargs)
        config = GitHubOidcConfig(
            owner=github_owner, repo=github_repo, allowed_branches=deploy_branches
        )

        provider = iam.OpenIdConnectProvider(
            self,
            "GitHubOidcProvider",
            url=f"https://{OIDC_PROVIDER_DOMAIN}",
            client_ids=[DEFAULT_AUDIENCE],
        )

        boundary = iam.ManagedPolicy(
            self,
            "DeployRoleBoundary",
            managed_policy_name="EndonDeployBoundary",
            document=iam.PolicyDocument.from_json(build_permissions_boundary()),
        )

        # Trust only the exact repo + branch(es) through the OIDC provider.
        principal = iam.OpenIdConnectPrincipal(
            provider,
            conditions={
                "StringEquals": {f"{OIDC_PROVIDER_DOMAIN}:aud": DEFAULT_AUDIENCE},
                "StringLike": {f"{OIDC_PROVIDER_DOMAIN}:sub": config.allowed_subjects()},
            },
        )
        self.deploy_role = iam.Role(
            self,
            "GitHubDeployRole",
            role_name="EndonDeploy-github-actions",
            assumed_by=principal,
            permissions_boundary=boundary,
            max_session_duration=None,
            description="Assumed by GitHub Actions via OIDC to deploy Endon AI (no long-lived keys).",
        )
        # The role may only assume the CDK bootstrap roles; the boundary caps everything else.
        for statement in build_identity_policy()["Statement"]:
            self.deploy_role.add_to_policy(iam.PolicyStatement.from_json(statement))

        CfnOutput(self, "DeployRoleArn", value=self.deploy_role.role_arn)
        CfnOutput(self, "OidcProviderArn", value=provider.open_id_connect_provider_arn)
