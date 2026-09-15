"""Lambda entry point: scan IAM on a schedule, publish findings, store an HTML report."""

from __future__ import annotations

import os
from typing import Any

from endon_core.aws import ClientFactory
from endon_core.config import Settings
from endon_core.events import EventBridgePublisher
from endon_core.findings import Severity
from endon_core.log import get_logger
from endon_core.timeutil import isoformat, utc_now
from endon_iam_analyzer.analyzer import IamAnalyzer
from endon_iam_analyzer.publish import publish_findings
from endon_iam_analyzer.reporting import render_html, render_json
from endon_iam_analyzer.snapshot import build_snapshot

logger = get_logger(__name__)


def lambda_handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    settings = Settings.from_env()
    clients = ClientFactory(region=settings.region)

    snapshot = build_snapshot(clients, region=settings.region)
    result = IamAnalyzer().analyze(snapshot)

    publisher = EventBridgePublisher(settings.event_bus_name, clients("events"))
    min_severity = Severity(os.environ.get("ENDON_IAM_PUBLISH_MIN_SEVERITY", "MEDIUM").upper())
    published = publish_findings(result, publisher, min_severity=min_severity)

    report_key = _store_report(clients, settings, result)
    logger.info(
        "IAM analysis complete",
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
    key = f"iam-assessments/{result.account_id}/{isoformat(utc_now(), 'seconds').replace(':', '')}.html"
    s3 = clients("s3")
    s3.put_object(
        Bucket=settings.evidence_bucket,
        Key=key,
        Body=render_html(result).encode("utf-8"),
        ContentType="text/html",
    )
    s3.put_object(
        Bucket=settings.evidence_bucket,
        Key=key.replace(".html", ".json"),
        Body=render_json(result).encode("utf-8"),
        ContentType="application/json",
    )
    return key
