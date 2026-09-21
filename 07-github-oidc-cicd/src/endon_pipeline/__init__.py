"""Endon AI passwordless GitHub -> AWS CI/CD.

Replaces long-lived AWS keys in CI with short-lived credentials obtained through GitHub's
OIDC provider. Two things are proven rather than assumed:

* the **OIDC trust** — only the exact repository and branch can assume the deploy role;
  forks, other branches, other repositories and pull requests cannot;
* the **blast radius** — the deploy role is scoped so a compromised pipeline can only
  assume the CDK bootstrap roles, and a permissions boundary denies privilege escalation.

The same pipeline runs the IAM analyzer (Project 2) and posture scanner (Project 3) as
security gates.
"""

from endon_pipeline.boundary import DeployRoleModel, build_deploy_role_model
from endon_pipeline.oidc import (
    GitHubClaims,
    GitHubOidcConfig,
    OidcTrustSimulator,
    build_trust_policy,
)

__all__ = [
    "DeployRoleModel",
    "GitHubClaims",
    "GitHubOidcConfig",
    "OidcTrustSimulator",
    "build_deploy_role_model",
    "build_trust_policy",
]
