"""Response engine: turns a security finding into a contained, fully documented incident."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from datetime import datetime
from typing import Any

from endon_core.aws import ClientFactory
from endon_core.config import ResponseMode, Settings
from endon_core.events import DetailType, EventPublisher, Source
from endon_core.findings import Finding, Resource
from endon_core.incidents import ActionKind, ActionRecord, ActionStatus, Incident, IncidentStatus
from endon_core.log import get_logger
from endon_core.store import IncidentStore
from endon_core.timeutil import isoformat, utc_now
from endon_detection.actions import REGISTRY, Action, ActionContext, ActionSkipped
from endon_detection.guardrails import Guardrails
from endon_detection.normalizers import normalize_event
from endon_detection.playbooks import Playbook, select_playbook

logger = get_logger(__name__)

_GUARDED = (ActionKind.CONTAIN, ActionKind.REMEDIATE)


class ResponseEngine:
    def __init__(
        self,
        *,
        settings: Settings,
        clients: ClientFactory,
        store: IncidentStore,
        publisher: EventPublisher,
        guardrails: Guardrails | None = None,
        registry: Mapping[str, Action] | None = None,
        clock: Callable[[], datetime] = utc_now,
    ) -> None:
        self.settings = settings
        self.clients = clients
        self.store = store
        self.publisher = publisher
        self.guardrails = guardrails or Guardrails(clients, settings.protected_tag_key)
        self.registry = registry or REGISTRY
        self._clock = clock

    def handle_event(self, event: Mapping[str, Any]) -> list[Incident]:
        findings = normalize_event(event)
        if not findings:
            logger.info(
                "Event ignored",
                extra={"eventSource": event.get("source"), "detailType": event.get("detail-type")},
            )
        return [self.handle_finding(finding) for finding in findings]

    def handle_finding(self, finding: Finding) -> Incident:
        playbook = select_playbook(finding)
        dry_run = self._is_dry_run(finding)
        incident = Incident.open(finding, playbook.name, opened_at=self._now())

        if self.store.create(incident):
            incident.log(
                "Incident opened",
                f"{finding.type} [{finding.severity}] matched playbook '{playbook.name}'",
                at=incident.opened_at,
            )
        else:
            existing = self.store.get(incident.incident_id)
            if existing is not None:
                # GuardDuty re-sends a finding each time the activity recurs. Only respond
                # again if the earlier response did not finish the job.
                existing.occurrences += 1
                reason = self._rerun_reason(existing, finding, dry_run)
                existing.finding = finding
                if reason is None:
                    existing.log(
                        "Finding re-observed",
                        f"Occurrence {existing.occurrences}; incident already {existing.status}",
                        at=self._now(),
                    )
                    self.store.save(existing)
                    return existing
                existing.log("Response re-run", reason, at=self._now())
                existing.playbook = playbook.name
                incident = existing

        self._respond(incident, playbook, dry_run)
        self.store.save(incident)
        self._publish_update(incident)
        logger.info(
            "Incident processed",
            extra={
                "incidentId": incident.incident_id,
                "status": incident.status.value,
                "playbook": incident.playbook,
                "findingType": finding.type,
            },
        )
        return incident

    def _respond(self, incident: Incident, playbook: Playbook, dry_run: bool) -> None:
        finding = incident.finding
        if dry_run:
            why = "GuardDuty sample finding" if finding.is_sample else "response mode is dry_run"
            incident.log("Dry run", f"No resources will be changed ({why})", at=self._now())

        ctx = ActionContext(
            finding=finding,
            incident=incident,
            clients=self.clients,
            settings=self.settings,
            publisher=self.publisher,
        )
        actions = [self.registry[name] for name in playbook.actions]
        first_record = len(incident.actions)

        for action in actions:
            if action.kind is not ActionKind.REPORT:
                self._run(action, ctx, playbook, dry_run)

        incident.status = self._outcome(incident.actions[first_record:], dry_run)
        if incident.status is IncidentStatus.CONTAINED and incident.contained_at is None:
            incident.contained_at = self._now()
            incident.log(
                "Containment complete",
                f"{incident.time_to_contain_seconds:.1f}s after the activity was first observed",
                at=incident.contained_at,
            )

        # Reports run last so they describe the final outcome.
        for action in actions:
            if action.kind is ActionKind.REPORT:
                self._run(action, ctx, playbook, dry_run)

    def _run(self, action: Action, ctx: ActionContext, playbook: Playbook, dry_run: bool) -> None:
        incident = ctx.incident
        targets = action.targets(ctx)
        if not targets:
            incident.actions.append(
                self._record(action, "-", ActionStatus.SKIPPED, action.not_applicable(ctx))
            )
            return
        for target in targets:
            status, message, data = self._execute(action, target, ctx, playbook, dry_run)
            incident.actions.append(self._record(action, target.id, status, message, data))
            if status is not ActionStatus.SKIPPED:
                incident.log(f"{action.name}: {status}", message, at=self._now())

    def _execute(
        self,
        action: Action,
        target: Resource,
        ctx: ActionContext,
        playbook: Playbook,
        dry_run: bool,
    ) -> tuple[ActionStatus, str, dict[str, Any]]:
        finding = ctx.finding
        if action.kind is ActionKind.CONTAIN and not finding.severity.at_least(
            playbook.min_severity
        ):
            return (
                ActionStatus.SKIPPED,
                f"Severity {finding.severity} is below the {playbook.min_severity} containment threshold",
                {},
            )
        if action.kind in _GUARDED and not finding.is_sample:
            reason = self.guardrails.check(target)
            if reason:
                return ActionStatus.SUPPRESSED, f"Guardrail: {reason}", {}
        if dry_run and action.kind is not ActionKind.REPORT:
            return ActionStatus.DRY_RUN, f"Would {action.plan(target, ctx)}", {}
        try:
            outcome = action.execute(target, ctx)
        except ActionSkipped as skipped:
            return ActionStatus.SKIPPED, str(skipped), {}
        except Exception as exc:  # one failed action must never stop the rest of the playbook
            logger.exception(
                "Response action failed",
                extra={
                    "action": action.name,
                    "target": target.id,
                    "incidentId": ctx.incident.incident_id,
                },
            )
            return ActionStatus.FAILED, f"{type(exc).__name__}: {exc}", {}
        return ActionStatus.SUCCEEDED, outcome.message, outcome.data

    @staticmethod
    def _outcome(records: list[ActionRecord], dry_run: bool) -> IncidentStatus:
        if dry_run:
            return IncidentStatus.DRY_RUN
        guarded = [r for r in records if r.kind in _GUARDED]
        succeeded = any(r.status is ActionStatus.SUCCEEDED for r in guarded)
        failed = any(r.status is ActionStatus.FAILED for r in guarded)
        if succeeded and failed:
            return IncidentStatus.PARTIALLY_CONTAINED
        if failed:
            return IncidentStatus.FAILED
        if succeeded:
            return IncidentStatus.CONTAINED
        if any(r.status is ActionStatus.SUPPRESSED for r in guarded):
            return IncidentStatus.SUPPRESSED
        return IncidentStatus.MONITORING

    @staticmethod
    def _rerun_reason(existing: Incident, finding: Finding, dry_run: bool) -> str | None:
        if existing.status in (IncidentStatus.FAILED, IncidentStatus.PARTIALLY_CONTAINED):
            return f"Previous response ended {existing.status}"
        if existing.status is IncidentStatus.DRY_RUN and not dry_run:
            return "Response mode is now enforce"
        if finding.severity.rank > existing.finding.severity.rank:
            return f"Severity escalated from {existing.finding.severity} to {finding.severity}"
        return None

    def _is_dry_run(self, finding: Finding) -> bool:
        return self.settings.response_mode is ResponseMode.DRY_RUN or finding.is_sample

    def _publish_update(self, incident: Incident) -> None:
        try:
            self.publisher.publish(
                Source.DETECTION,
                DetailType.INCIDENT_UPDATED,
                {"incident": incident.to_dict(include_raw=False)},
                resources=[r.id for r in incident.finding.resources],
            )
        except Exception:  # the incident is already stored; a lost update must not undo it
            logger.exception(
                "Failed to publish incident update", extra={"incidentId": incident.incident_id}
            )

    def _record(
        self,
        action: Action,
        target: str,
        status: ActionStatus,
        message: str,
        data: dict[str, Any] | None = None,
    ) -> ActionRecord:
        return ActionRecord(
            action=action.name,
            kind=action.kind,
            target=target,
            status=status,
            message=message,
            at=self._now(),
            data=data or {},
        )

    def _now(self) -> str:
        return isoformat(self._clock())
