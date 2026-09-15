"""Forensics engine: turn a forensics request into a complete, hashed, immutable case."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from typing import Any

from endon_core.aws import ClientFactory
from endon_core.config import Settings
from endon_core.events import DetailType, EventPublisher, Source
from endon_core.log import get_logger
from endon_core.timeutil import isoformat, utc_now
from endon_forensics.collectors import DEFAULT_COLLECTORS
from endon_forensics.collectors.base import Collector, CollectorContext
from endon_forensics.evidence_store import EvidenceStore
from endon_forensics.isolation import verify_isolation
from endon_forensics.models import CaseStatus, EvidenceItem, EvidenceStatus, ForensicCase

logger = get_logger(__name__)


class ForensicsEngine:
    def __init__(
        self,
        *,
        settings: Settings,
        clients: ClientFactory,
        store: EvidenceStore,
        publisher: EventPublisher,
        collectors: Iterable[Collector] | None = None,
    ) -> None:
        self.settings = settings
        self.clients = clients
        self.store = store
        self.publisher = publisher
        self.collectors = sorted(collectors or DEFAULT_COLLECTORS, key=lambda c: c.order)

    def handle_event(self, event: Mapping[str, Any]) -> ForensicCase | None:
        if event.get("detail-type") != DetailType.FORENSICS_REQUESTED:
            logger.info("Ignoring event", extra={"detailType": event.get("detail-type")})
            return None
        return self.collect(event["detail"])

    def collect(self, detail: Mapping[str, Any]) -> ForensicCase:
        case = ForensicCase.from_request(detail)
        case.collector_identity = self._identity()
        case.log(
            "Forensics requested", f"{case.finding_type} on {case.instance_id}", at=case.opened_at
        )

        # Idempotent: a re-delivered request for a case already collected does not re-snapshot.
        if self.store.case_exists(case.case_id):
            case.status = CaseStatus.SKIPPED
            case.completed_at = self._now()
            case.log("Case already exists", "A manifest is already stored; skipping re-collection")
            self._publish(case)
            logger.info("Forensic case already exists", extra={"caseId": case.case_id})
            return case

        case.isolation = verify_isolation(self.clients, case.instance_id)
        case.log(
            "Isolation verified",
            "contained"
            if case.isolation.get("contained")
            else f"NOT contained: {case.isolation.get('notes')}",
        )

        ctx = CollectorContext(case=case, clients=self.clients, store=self.store)
        for collector in self.collectors:
            for item in self._run(collector, ctx):
                case.add(item)
                case.log(f"{collector.id}: {item.status}", item.description)

        case.status = self._status(case)
        case.completed_at = self._now()
        self._write_manifest(case)
        self._publish(case)
        logger.info(
            "Forensic case complete",
            extra={
                "caseId": case.case_id,
                "status": case.status.value,
                "evidence": len(case.evidence),
                "snapshots": len(case.snapshot_ids),
            },
        )
        return case

    def _run(self, collector: Collector, ctx: CollectorContext) -> list[EvidenceItem]:
        try:
            return collector.collect(ctx)
        except Exception as exc:  # one collector failing must not lose the rest of the evidence
            logger.exception(
                "Collector failed", extra={"collector": collector.id, "caseId": ctx.case.case_id}
            )
            return [
                EvidenceItem(
                    id=collector.id,
                    kind=collector.kind,
                    description=f"{collector.id} (failed)",
                    status=EvidenceStatus.FAILED,
                    collector=collector.id,
                    detail={"error": f"{type(exc).__name__}: {exc}"},
                )
            ]

    def _status(self, case: ForensicCase) -> CaseStatus:
        critical_ids = {c.id for c in self.collectors if c.critical}
        # Map evidence back to whether each critical collector produced anything collected.
        critical_ok = {
            item.collector
            for item in case.evidence
            if item.collector in critical_ids and item.collected
        }
        critical_failed = critical_ids - critical_ok
        any_collected = any(item.collected for item in case.evidence)
        if not any_collected:
            return CaseStatus.FAILED
        return CaseStatus.COLLECTED if not critical_failed else CaseStatus.PARTIAL

    def _write_manifest(self, case: ForensicCase) -> None:
        manifest = case.manifest()
        stored = self.store.write_manifest(case.case_id, manifest)
        case.manifest_key = stored.key
        case.manifest_sha256 = stored.sha256

    def _publish(self, case: ForensicCase) -> None:
        detail = {
            "incidentId": case.incident_id,
            "caseId": case.case_id,
            "instanceId": case.instance_id,
            "instanceArn": case.instance_arn,
            "accountId": case.account_id,
            "region": case.region,
            "status": case.status.value,
            "evidenceCount": sum(1 for e in case.evidence if e.collected),
            "snapshotIds": case.snapshot_ids,
            "manifestKey": case.manifest_key,
            "manifestSha256": case.manifest_sha256,
            "completedAt": case.completed_at,
        }
        try:
            self.publisher.publish(
                Source.FORENSICS,
                DetailType.FORENSICS_COMPLETED,
                detail,
                resources=[case.instance_arn] if case.instance_arn else [],
            )
        except Exception:  # the case is already stored; a lost notification must not undo it
            logger.exception(
                "Failed to publish forensics completion", extra={"caseId": case.case_id}
            )

    def _identity(self) -> str:
        try:
            return self.clients("sts").get_caller_identity()["Arn"]
        except Exception:
            return "unknown"

    def _now(self) -> str:
        return isoformat(utc_now())
