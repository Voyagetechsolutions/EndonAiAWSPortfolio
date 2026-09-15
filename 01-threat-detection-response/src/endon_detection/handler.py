"""Lambda entry point for the response engine."""

from __future__ import annotations

from typing import Any

from endon_core.aws import ClientFactory, role_names_from_arn
from endon_core.config import Settings
from endon_core.events import EventBridgePublisher
from endon_core.store import DynamoDBIncidentStore
from endon_detection.engine import ResponseEngine
from endon_detection.guardrails import Guardrails

_engine: ResponseEngine | None = None


def build_engine(settings: Settings | None = None) -> ResponseEngine:
    settings = settings or Settings.from_env()
    clients = ClientFactory(region=settings.region)
    caller_arn = clients("sts").get_caller_identity()["Arn"]
    return ResponseEngine(
        settings=settings,
        clients=clients,
        store=DynamoDBIncidentStore(settings.incidents_table, clients("dynamodb")),
        publisher=EventBridgePublisher(settings.event_bus_name, clients("events")),
        guardrails=Guardrails(
            clients,
            settings.protected_tag_key,
            responder_role_names=role_names_from_arn(caller_arn),
        ),
    )


def lambda_handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    global _engine
    if _engine is None:  # built once per execution environment, reused on warm starts
        _engine = build_engine()
    incidents = _engine.handle_event(event)
    return {
        "processed": len(incidents),
        "incidents": [
            {"incidentId": i.incident_id, "status": i.status.value, "playbook": i.playbook}
            for i in incidents
        ],
    }
