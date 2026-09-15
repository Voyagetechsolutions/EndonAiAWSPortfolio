"""Lambda entry points: the event consumer and the scheduled secrets scanner."""

from __future__ import annotations

import os
from typing import Any

from endon_core.aws import ClientFactory
from endon_core.config import Settings
from endon_core.events import EventBridgePublisher
from endon_core.findings import Severity
from endon_core.log import get_logger
from endon_core.timeutil import isoformat, utc_now
from endon_dataprotection.normalizers import normalize_event
from endon_dataprotection.publish import publish_findings
from endon_dataprotection.scanner import DataProtectionScanner

logger = get_logger(__name__)

_publisher: EventBridgePublisher | None = None


def _events_publisher(settings: Settings, clients: ClientFactory) -> EventBridgePublisher:
    global _publisher
    if _publisher is None:
        _publisher = EventBridgePublisher(settings.event_bus_name, clients("events"))
    return _publisher


def event_handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    """Consume a Macie finding or an AWS Health credential-exposure event."""
    settings = Settings.from_env()
    clients = ClientFactory(region=settings.region)
    findings = normalize_event(event)
    if not findings:
        return {"published": 0}
    published = publish_findings(findings, _events_publisher(settings, clients))
    logger.info(
        "Data-protection event handled",
        extra={"source": event.get("source"), "published": published},
    )
    return {"published": published, "types": [f.type for f in findings]}


def scan_handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    """Scheduled scan for secrets in Lambda env vars, EC2 user data and Secrets Manager."""
    settings = Settings.from_env()
    clients = ClientFactory(region=settings.region)
    result = DataProtectionScanner().scan_account(clients, region=settings.region)

    publisher = EventBridgePublisher(settings.event_bus_name, clients("events"))
    min_severity = Severity(os.environ.get("ENDON_DP_PUBLISH_MIN_SEVERITY", "MEDIUM").upper())
    published = publish_findings(result.findings, publisher, min_severity=min_severity)

    report_key = _store_report(clients, settings, result)
    logger.info(
        "Data-protection scan complete",
        extra={"score": result.score, "findings": len(result.findings), "published": published},
    )
    return {
        "account": result.account_id,
        "score": result.score,
        "findings": len(result.findings),
        "published": published,
        "counts": result.counts,
        "report": report_key,
    }


def _store_report(clients: ClientFactory, settings: Settings, result) -> str | None:
    if not settings.evidence_bucket:
        return None
    from endon_dataprotection.reporting import render_json

    stamp = isoformat(utc_now(), "seconds").replace(":", "")
    key = f"data-protection/{result.account_id}/{result.region}/{stamp}.json"
    clients("s3").put_object(
        Bucket=settings.evidence_bucket,
        Key=key,
        Body=render_json(result).encode("utf-8"),
        ContentType="application/json",
    )
    return key
