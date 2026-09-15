"""Publish data-protection findings onto the Endon security bus."""

from __future__ import annotations

from collections.abc import Iterable

from endon_core.events import DetailType, EventPublisher, Source
from endon_core.findings import Finding, Severity
from endon_core.log import get_logger

logger = get_logger(__name__)


def publish_findings(
    findings: Iterable[Finding], publisher: EventPublisher, min_severity: Severity = Severity.LOW
) -> int:
    published = 0
    for finding in findings:
        if not finding.severity.at_least(min_severity):
            continue
        finding.source = Source.DATA_PROTECTION
        publisher.publish(
            Source.DATA_PROTECTION,
            DetailType.FINDING,
            {"finding": finding.to_dict(include_raw=False)},
            resources=[r.id for r in finding.resources if r.id.startswith("arn:")],
        )
        published += 1
    logger.info("Published data-protection findings", extra={"count": published})
    return published
