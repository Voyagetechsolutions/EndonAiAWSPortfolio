"""Wildcard and NotAction over-permission in customer-managed and inline policies.

Admin (`*` on `*`) is reported by the admin check. This check catches the next tier:
wildcards on sensitive services, and `NotAction` with `Allow`, which grants everything
except a named few and is almost always a mistake.
"""

from __future__ import annotations

from collections.abc import Iterator

from endon_core.findings import Finding, Resource, Severity
from endon_iam_analyzer.checks.base import CheckContext, check
from endon_iam_analyzer.models import ManagedPolicy
from endon_iam_analyzer.policy import PolicyDocument, Statement

# Services where a `service:*` grant is high-impact on its own.
SENSITIVE_SERVICES = {
    "iam": Severity.HIGH,
    "sts": Severity.HIGH,
    "organizations": Severity.HIGH,
    "kms": Severity.HIGH,
    "secretsmanager": Severity.HIGH,
    "ec2": Severity.MEDIUM,
    "s3": Severity.MEDIUM,
    "lambda": Severity.MEDIUM,
    "dynamodb": Severity.MEDIUM,
}


@check
def wildcard_permissions(ctx: CheckContext) -> Iterator[Finding]:
    for name, document, resource in _policies_to_scan(ctx):
        yield from _scan_document(ctx, name, document, resource)


def _policies_to_scan(ctx: CheckContext):
    seen: set[str] = set()
    for policy in ctx.snapshot.policies.values():
        if policy.is_aws_managed or policy.attachment_count == 0:
            continue
        seen.add(policy.arn)
        yield policy.name, policy.document, _policy_resource(policy)
    for principal in ctx.snapshot.principals():
        for inline_name, document in principal.inline_policies.items():
            label = f"{principal.name}:{inline_name}"
            yield label, document, principal.to_resource()


def _scan_document(
    ctx: CheckContext, policy_name: str, document: PolicyDocument, resource: Resource
) -> Iterator[Finding]:
    reported_services: set[str] = set()
    for index, statement in enumerate(document.statements):
        if not statement.is_allow:
            continue
        if statement.not_actions:
            yield _notaction_finding(ctx, policy_name, statement, resource, index)
            continue
        if "*" in statement.actions or "*:*" in statement.actions:
            # Full admin wildcard is the admin check's job unless the resource is scoped.
            if not statement.grants_on_any_resource():
                yield _wildcard_finding(
                    ctx, policy_name, "*", Severity.HIGH, statement, resource, index
                )
            continue
        for service, severity in _wildcard_services(statement):
            if service in reported_services:
                continue
            reported_services.add(service)
            yield _wildcard_finding(
                ctx, policy_name, f"{service}:*", severity, statement, resource, index
            )


def _wildcard_services(statement: Statement) -> Iterator[tuple[str, Severity]]:
    for action in statement.actions:
        if action.endswith(":*") and action != "*:*":
            service = action.split(":", 1)[0]
            if service in SENSITIVE_SERVICES:
                yield service, SENSITIVE_SERVICES[service]


def _wildcard_finding(ctx, policy_name, pattern, severity, statement, resource, index) -> Finding:
    scope = "any resource" if statement.grants_on_any_resource() else "a scoped resource"
    return ctx.finding(
        finding_type="IAM:Policy/WildcardAction",
        title=f"Policy {policy_name} allows {pattern} on {scope}",
        severity=severity if statement.grants_on_any_resource() else Severity.MEDIUM,
        resources=[resource],
        description=(
            f"Statement {statement.sid or index} in policy '{policy_name}' allows the wildcard "
            f"action '{pattern}'. Wildcard grants accumulate unintended permissions as AWS adds APIs."
        ),
        remediation="List the specific actions in use. Access Advisor shows which services are actually called.",
        control_id="IAM-WILDCARD-001",
        tags={"policy": policy_name, "pattern": pattern},
    )


def _notaction_finding(ctx, policy_name, statement, resource, index) -> Finding:
    excepted = ", ".join(statement.not_actions) or "nothing"
    return ctx.finding(
        finding_type="IAM:Policy/NotActionWithAllow",
        title=f"Policy {policy_name} allows all actions except a few (NotAction)",
        severity=Severity.HIGH if statement.grants_on_any_resource() else Severity.MEDIUM,
        resources=[resource],
        description=(
            f"Statement {statement.sid or index} in policy '{policy_name}' uses Allow with NotAction, "
            f"granting every action except: {excepted}. This grants far more than it appears to."
        ),
        remediation="Rewrite as an explicit Allow of the actions that are needed.",
        control_id="IAM-NOTACTION-001",
        tags={"policy": policy_name},
    )


def _policy_resource(policy: ManagedPolicy) -> Resource:
    return Resource("AwsIamPolicy", policy.arn, details={"name": policy.name})
