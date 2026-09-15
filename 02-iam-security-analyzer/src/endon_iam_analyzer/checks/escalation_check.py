"""Turn privilege-escalation analysis into findings."""

from __future__ import annotations

from collections.abc import Iterator

from endon_core.findings import Finding
from endon_iam_analyzer import escalation
from endon_iam_analyzer.checks.base import CheckContext, check, lower_severity
from endon_iam_analyzer.escalation import EscalationResult, TechniqueMatch


@check
def privilege_escalation(ctx: CheckContext) -> Iterator[Finding]:
    for result in escalation.analyze(ctx.snapshot).values():
        yield _finding(ctx, result)


def _finding(ctx: CheckContext, result: EscalationResult) -> Finding:
    principal = result.principal
    direct = result.direct
    severity = max((m.effective_severity for m in _all_matches(result)), key=lambda s: s.rank)
    suffix = ""
    if principal.is_protected:
        severity, suffix = lower_severity(severity), " (tagged endon:protected)"

    lines = []
    if direct:
        lines.append("Direct techniques: " + ", ".join(_describe(m) for m in direct))
    for role_name, reachable in result.via_roles.items():
        path = " -> ".join(reachable.path)
        techniques = ", ".join(m.technique.id for m in reachable.matches)
        lines.append(f"Via assumable role '{role_name}' ({path}): {techniques}")

    return ctx.finding(
        finding_type=f"IAM:{principal.kind.capitalize()}/PrivilegeEscalation",
        title=f"{principal.kind.capitalize()} {principal.name} can escalate to administrator{suffix}",
        severity=severity,
        resources=[principal.to_resource()],
        description=(
            f"The {principal.kind} '{principal.name}' holds permissions that let it grant itself "
            "further access, reaching administrator-equivalent power. " + " ".join(lines)
        ),
        remediation=(
            "Remove or scope the escalation permissions listed above. Where the permission is needed, "
            "add a PermissionsBoundary or a condition that prevents self-elevation."
        ),
        control_id="IAM-ESCALATION-001",
        tags={
            "principalKind": principal.kind,
            "directTechniques": ",".join(m.technique.id for m in direct),
            "viaRoles": ",".join(result.via_roles),
        },
    )


def _all_matches(result: EscalationResult) -> Iterator[TechniqueMatch]:
    yield from result.direct
    for reachable in result.via_roles.values():
        yield from reachable.matches


def _describe(match: TechniqueMatch) -> str:
    confidence = "" if match.confidence == "high" else f" [{match.confidence}]"
    return f"{match.technique.id} (via {'+'.join(match.actions_used)}){confidence}"
