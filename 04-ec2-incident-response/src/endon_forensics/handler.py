"""Lambda entry point: consume Endon Forensics Requested, collect evidence."""

from __future__ import annotations

from typing import Any

from endon_core.aws import ClientFactory
from endon_core.config import Settings
from endon_core.events import EventBridgePublisher
from endon_forensics.engine import ForensicsEngine
from endon_forensics.evidence_store import EvidenceStore

_engine: ForensicsEngine | None = None


def build_engine(settings: Settings | None = None) -> ForensicsEngine:
    settings = settings or Settings.from_env()
    if not settings.evidence_bucket:
        raise RuntimeError("ENDON_EVIDENCE_BUCKET is required for the forensics engine")
    clients = ClientFactory(region=settings.region)
    return ForensicsEngine(
        settings=settings,
        clients=clients,
        store=EvidenceStore(settings.evidence_bucket, clients("s3")),
        publisher=EventBridgePublisher(settings.event_bus_name, clients("events")),
    )


def lambda_handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    global _engine
    if _engine is None:
        _engine = build_engine()
    case = _engine.handle_event(event)
    if case is None:
        return {"handled": False}
    return {
        "handled": True,
        "caseId": case.case_id,
        "status": case.status.value,
        "evidenceCount": sum(1 for e in case.evidence if e.collected),
        "snapshotIds": case.snapshot_ids,
        "manifestKey": case.manifest_key,
    }
