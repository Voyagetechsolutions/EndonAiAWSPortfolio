"""Administrator-equivalent access held by users, roles and groups."""

from __future__ import annotations

from collections.abc import Iterator

from endon_core.findings import Finding, Severity
from endon_iam_analyzer.checks.base import CheckContext, check, lower_severity


@check
def administrator_access(ctx: CheckContext) -> Iterator[Finding]:
    for principal in ctx.snapshot.principals():
        if principal.is_service_linked_role:
            continue
        permissions = ctx.snapshot.permissions_for(principal)
        if not permissions.grants_admin():
            continue

        severity = Severity.CRITICAL
        suffix = ""
        if principal.is_protected:
            severity, suffix = lower_severity(severity), " (tagged endon:protected)"

        yield ctx.finding(
            finding_type=f"IAM:{principal.kind.capitalize()}/AdministratorAccess",
            title=f"{principal.kind.capitalize()} {principal.name} has administrator-equivalent access{suffix}",
            severity=severity,
            resources=[principal.to_resource()],
            description=(
                f"The {principal.kind} '{principal.name}' effectively has Action:'*' on "
                "Resource:'*' with no condition. A single compromised credential for this "
                "principal is a full account takeover."
            ),
            remediation=(
                "Replace the wildcard grant with the specific actions this principal uses "
                "(see the least-privilege policy generated from Access Advisor). Require MFA, "
                "and prefer short-lived role sessions over long-lived admin users."
            ),
            control_id="IAM-ADMIN-001",
            tags={"principalKind": principal.kind},
        )
