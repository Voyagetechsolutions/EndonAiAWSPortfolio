"""Build a live, DynamoDB-backed SOC service from the platform's settings.

Kept separate from the app factory so the app has no import-time AWS dependency: tests build a
service over in-memory stores, and the Lambda builds one over the real tables, through the same
``create_app``.
"""

from __future__ import annotations

from endon_core.aws import ClientFactory
from endon_core.config import Settings
from endon_core.store import DynamoDBFindingStore, DynamoDBIncidentStore
from endon_soc.health import probe_detective_services
from endon_soc.service import SocService


def build_live_service(settings: Settings, clients: ClientFactory) -> SocService:
    dynamodb = clients("dynamodb")
    return SocService(
        incidents=DynamoDBIncidentStore(settings.incidents_table, dynamodb),
        findings=DynamoDBFindingStore(settings.findings_table, dynamodb),
        health=probe_detective_services(clients),
    )
