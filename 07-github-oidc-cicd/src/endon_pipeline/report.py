"""Print the pipeline's security posture: the OIDC trust proof and the blast-radius proof."""

from __future__ import annotations

from endon_pipeline.boundary import build_deploy_role_model
from endon_pipeline.oidc import (
    GitHubClaims,
    GitHubOidcConfig,
    OidcTrustSimulator,
    build_trust_policy,
)

# Who might try to assume the deploy role, and whether they should be able to.
TRUST_CHECKS = [
    (
        "Push to main of our repo",
        lambda repo: GitHubClaims(repository=repo, ref="refs/heads/main"),
        True,
    ),
    (
        "Push to a feature branch",
        lambda repo: GitHubClaims(repository=repo, ref="refs/heads/feature-x"),
        False,
    ),
    (
        "A pull request",
        lambda repo: GitHubClaims(repository=repo, event_name="pull_request"),
        False,
    ),
    (
        "A fork / different owner",
        lambda repo: GitHubClaims(repository="attacker/endon-ai", ref="refs/heads/main"),
        False,
    ),
    (
        "A different repository",
        lambda repo: GitHubClaims(repository="acme/other", ref="refs/heads/main"),
        False,
    ),
    ("A git tag", lambda repo: GitHubClaims(repository=repo, ref="refs/tags/v1.0"), False),
]

# What a compromised pipeline would try, and whether the deploy role can do it.
BLAST_CHECKS = [
    (
        "Assume the CDK deploy role",
        "sts:AssumeRole",
        "arn:aws:iam::123456789012:role/cdk-hnb659fds-deploy-role-1-us-east-1",
    ),
    ("Create an IAM user (persistence)", "iam:CreateUser", "*"),
    ("Create an access key", "iam:CreateAccessKey", "*"),
    ("Attach AdministratorAccess to itself", "iam:AttachUserPolicy", "*"),
    ("Pass a privileged role", "iam:PassRole", "*"),
    ("Delete an S3 bucket (destroy data)", "s3:DeleteBucket", "*"),
    ("Leave the organization", "organizations:LeaveOrganization", "*"),
]


def render_console(config: GitHubOidcConfig | None = None) -> str:
    config = config or GitHubOidcConfig(owner="mthokozisi-chaza", repo="endon-ai")
    simulator = OidcTrustSimulator(build_trust_policy(config, account_id="123456789012"))
    model = build_deploy_role_model()

    lines = ["ENDON AI - PASSWORDLESS CI/CD PIPELINE", "=" * 38]
    lines.append(
        f"Repository: {config.repository}   Deploy branch: {', '.join(config.allowed_branches)}"
    )
    lines.append("No long-lived AWS keys. GitHub Actions -> OIDC -> STS -> scoped deploy role.")

    lines += ["", "WHO CAN ASSUME THE DEPLOY ROLE (GitHub OIDC trust)", "-" * 49]
    trust_ok = True
    for description, make_claims, expected in TRUST_CHECKS:
        allowed = simulator.can_assume(make_claims(config.repository))
        mark = "ALLOWED" if allowed else "DENIED "
        lines.append(f"  [{mark}] {description}")
        trust_ok = trust_ok and (allowed == expected)

    lines += ["", "BLAST RADIUS OF A COMPROMISED PIPELINE (deploy role + boundary)", "-" * 62]
    contained = True
    for description, action, resource in BLAST_CHECKS:
        allowed = model.can(action, resource)
        mark = "ALLOWED" if allowed else "DENIED "
        lines.append(f"  [{mark}] {description}")
        if action != "sts:AssumeRole":
            contained = contained and not allowed

    denied_trust = sum(
        1
        for _, m, exp in TRUST_CHECKS
        if not exp and not simulator.can_assume(m(config.repository))
    )
    denied_blast = sum(
        1 for _, a, r in BLAST_CHECKS if a != "sts:AssumeRole" and not model.can(a, r)
    )
    lines += [
        "",
        f"  {denied_trust}/{sum(1 for _, _, e in TRUST_CHECKS if not e)} unauthorized assume attempts denied.",
        f"  {denied_blast}/{sum(1 for _, a, _ in BLAST_CHECKS if a != 'sts:AssumeRole')} dangerous pipeline actions denied.",
    ]
    if not (trust_ok and contained):
        lines.append("  WARNING: a check did not match the expected outcome.")
    return "\n".join(lines)
