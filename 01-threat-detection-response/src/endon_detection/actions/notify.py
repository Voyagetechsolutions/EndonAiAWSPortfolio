"""Tell the security team what happened and what the engine already did about it."""

from __future__ import annotations

from endon_core.findings import Resource
from endon_core.incidents import ActionKind, Incident, IncidentStatus
from endon_detection.actions.base import Action, ActionContext, ActionOutcome, ActionSkipped

# Incidents where the engine acted (or would have) are always reported, whatever the severity.
_ALWAYS_REPORT = {
    IncidentStatus.CONTAINED,
    IncidentStatus.PARTIALLY_CONTAINED,
    IncidentStatus.FAILED,
    IncidentStatus.SUPPRESSED,
    IncidentStatus.DRY_RUN,
}
_SUBJECT_LIMIT = 100


class NotifySecurityTeam(Action):
    name = "notify"
    kind = ActionKind.REPORT

    def targets(self, ctx: ActionContext) -> list[Resource]:
        topic = ctx.settings.alerts_topic_arn
        return [Resource("AwsSnsTopic", topic)] if topic else []

    def not_applicable(self, ctx: ActionContext) -> str:
        return "No alerts topic is configured"

    def plan(self, target: Resource, ctx: ActionContext) -> str:
        return f"send an incident alert to {target.name}"

    def execute(self, target: Resource, ctx: ActionContext) -> ActionOutcome:
        incident, finding = ctx.incident, ctx.finding
        if incident.status not in _ALWAYS_REPORT and not finding.severity.at_least(
            ctx.settings.notify_min_severity
        ):
            raise ActionSkipped(
                f"Severity {finding.severity} is below the {ctx.settings.notify_min_severity} alert threshold"
            )
        ctx.clients("sns").publish(
            TopicArn=target.id, Subject=alert_subject(incident), Message=alert_message(incident)
        )
        return ActionOutcome(f"Alert sent to {target.name}", {"topicArn": target.id})


def alert_subject(incident: Incident) -> str:
    finding = incident.finding
    subject = f"[Endon AI][{finding.severity}][{incident.status}] {finding.title}"
    # SNS subjects must be printable ASCII without line breaks, at most 100 characters.
    subject = "".join(ch for ch in subject if 32 <= ord(ch) < 127)
    return subject[:_SUBJECT_LIMIT]


def alert_message(incident: Incident) -> str:
    finding = incident.finding
    lines = [f"Endon AI security incident {incident.incident_id}"]
    if finding.is_sample:
        lines.append("NOTE: GuardDuty sample finding - no resources were changed.")
    lines += [
        "",
        f"Status:    {incident.status}",
        f"Severity:  {finding.severity}",
        f"Finding:   {finding.type}",
        f"Title:     {finding.title}",
        f"Account:   {finding.account_id} ({finding.region})",
        f"Playbook:  {incident.playbook}",
        f"Detected:  {incident.detected_at}",
    ]
    if incident.time_to_contain_seconds is not None:
        lines.append(
            f"Contained: {incident.contained_at} ({incident.time_to_contain_seconds:.1f}s after detection)"
        )
    lines += ["", "Affected resources:"]
    lines += [f"  - {r.type} {r.id}" for r in finding.resources] or ["  - none listed"]
    lines += ["", "Response actions:"]
    lines += [f"  [{a.status}] {a.action} -> {a.message}" for a in incident.actions] or ["  - none"]
    return "\n".join(lines)
