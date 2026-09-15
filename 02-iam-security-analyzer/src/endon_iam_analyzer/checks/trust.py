"""Dangerous role trust policies: who is allowed to assume a role.

A role is only as safe as the principals its trust policy admits. The high-impact
mistakes are trusting an external AWS account without an ExternalId (the classic
confused-deputy condition), and trusting ``"*"`` (anyone, anywhere).
"""

from __future__ import annotations

from collections.abc import Iterator

from endon_core.findings import Finding, Severity
from endon_iam_analyzer.checks.base import CheckContext, check
from endon_iam_analyzer.models import Principal
from endon_iam_analyzer.policy import Statement

_EXTERNAL_ID_CONDITIONS = {"sts:externalid"}


@check
def role_trust_policies(ctx: CheckContext) -> Iterator[Finding]:
    account_root_suffix = f":{ctx.account_id}:root"
    for role in ctx.snapshot.roles.values():
        if role.is_service_linked_role or role.trust_policy is None:
            continue
        for index, statement in enumerate(role.trust_policy.statements):
            if not statement.is_allow or not statement.matches_action("sts:assumerole"):
                continue
            yield from _evaluate_statement(ctx, role, statement, index, account_root_suffix)


def _evaluate_statement(
    ctx: CheckContext, role: Principal, statement: Statement, index: int, account_root_suffix: str
) -> Iterator[Finding]:
    aws_principals = _aws_principals(statement.principal)
    has_external_id = _has_external_id_condition(statement.conditions)

    for value in aws_principals:
        if value == "*":
            yield _any_principal_finding(ctx, role, has_external_id)
            continue
        if _is_external_account(value, ctx.account_id, account_root_suffix) and not has_external_id:
            yield _external_account_finding(ctx, role, value)


def _any_principal_finding(ctx: CheckContext, role: Principal, has_external_id: bool) -> Finding:
    gated = (
        " (a Condition is present, but Principal:'*' should never be used)"
        if has_external_id
        else ""
    )
    return ctx.finding(
        finding_type="IAM:Role/TrustsAnyPrincipal",
        title=f"Role {role.name} can be assumed by any AWS principal",
        severity=Severity.CRITICAL,
        resources=[role.to_resource()],
        description=(
            f"Role '{role.name}' has a trust policy with Principal:'*'{gated}. Any AWS account "
            "can attempt to assume this role."
        ),
        remediation="Restrict the trust policy Principal to specific role or account ARNs.",
        control_id="IAM-TRUST-001",
        tags={"role": role.name},
    )


def _external_account_finding(ctx: CheckContext, role: Principal, principal_value: str) -> Finding:
    return ctx.finding(
        finding_type="IAM:Role/TrustsExternalAccount",
        title=f"Role {role.name} trusts an external account without an ExternalId",
        severity=Severity.HIGH,
        resources=[role.to_resource()],
        description=(
            f"Role '{role.name}' trusts '{principal_value}', which is outside this account, with no "
            "sts:ExternalId condition. This is the confused-deputy pattern: a third party can be "
            "tricked into assuming the role on an attacker's behalf."
        ),
        remediation="Add a Condition on sts:ExternalId (a shared secret), or remove the external trust.",
        control_id="IAM-TRUST-002",
        tags={"role": role.name, "trustedPrincipal": principal_value},
    )


def _aws_principals(principal) -> list[str]:
    if principal is None:
        return []
    if isinstance(principal, str):
        return [principal] if principal == "*" else []
    aws = principal.get("AWS")
    if aws is None:
        return []
    return aws if isinstance(aws, list) else [aws]


def _is_external_account(value: str, account_id: str, account_root_suffix: str) -> bool:
    if account_id in value:
        return False
    return value.startswith("arn:") or value.isdigit() or value.endswith(":root")


def _has_external_id_condition(conditions) -> bool:
    for keys in conditions.values():
        if isinstance(keys, dict) and any(k.lower() in _EXTERNAL_ID_CONDITIONS for k in keys):
            return True
    return False
