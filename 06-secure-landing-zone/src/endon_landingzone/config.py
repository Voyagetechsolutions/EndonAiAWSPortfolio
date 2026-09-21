"""Landing-zone configuration: approved regions and the principals guardrails exempt."""

from __future__ import annotations

# Regions the organization is allowed to operate in. Everything else is denied by SCP.
APPROVED_REGIONS = ("us-east-1", "eu-west-1")

# Principals that guardrails must not block: the security administrator (break-glass and
# security operations) and the CI/CD deployment role that manages the Endon platform.
# These are matched as aws:PrincipalArn patterns, so they hold in every member account.
SECURITY_ADMIN_ARN = "arn:aws:iam::*:role/EndonSecurityAdmin"
BREAK_GLASS_ARN = "arn:aws:iam::*:role/EndonBreakGlass"
DEPLOY_ROLE_ARN = "arn:aws:iam::*:role/EndonDeploy*"

# Guardrails on logging/detection exempt the security administrator and break-glass only.
PROTECTED_SERVICE_EXEMPTIONS = (SECURITY_ADMIN_ARN, BREAK_GLASS_ARN)

# Guardrails on the Endon platform's own resources also exempt the deployment pipeline.
ENDON_RESOURCE_EXEMPTIONS = (SECURITY_ADMIN_ARN, BREAK_GLASS_ARN, DEPLOY_ROLE_ARN)

# Services whose actions are global (region-agnostic) and must not be caught by the
# region-allowlist guardrail.
GLOBAL_SERVICE_ACTIONS = (
    "iam:*",
    "organizations:*",
    "sts:*",
    "account:*",
    "cloudfront:*",
    "route53:*",
    "route53domains:*",
    "globalaccelerator:*",
    "waf:*",
    "support:*",
    "trustedadvisor:*",
    "health:*",
    "budgets:*",
    "ce:*",
    "sso:*",
    "sso-directory:*",
    "identitystore:*",
    "artifact:*",
    "shield:*",
    "networkmanager:*",
)
