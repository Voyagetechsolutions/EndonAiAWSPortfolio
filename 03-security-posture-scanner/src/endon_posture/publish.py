"""Publish posture findings onto the Endon security bus.

Posture findings are mostly informational to the response engine (routed to triage).
The exception is ``Posture:S3/BucketPubliclyAccessible``, which the Project 1 response
engine auto-remediates by re-enabling S3 Block Public Access - the posture scanner
detects the exposure Project 1's GuardDuty feed would not, and Project 1 closes it.
"""

from __future__ import annotations

from endon_core.events import DetailType, EventPublisher, Source
from endon_core.findings import Severity
from endon_core.log import get_logger
from endon_posture.scanner import ScanResult

logger = get_logger(__name__)


def publish_findings(
    result: ScanResult, publisher: EventPublisher, min_severity: Severity = Severity.HIGH
) -> int:
    published = 0
    for finding in result.findings:
        if not finding.severity.at_least(min_severity):
            continue
        finding.source = Source.POSTURE_SCANNER
        publisher.publish(
            Source.POSTURE_SCANNER,
            DetailType.FINDING,
            {"finding": finding.to_dict(include_raw=False)},
            resources=[r.id for r in finding.resources if r.id.startswith("arn:")],
        )
        published += 1
    logger.info(
        "Published posture findings", extra={"account": result.account_id, "count": published}
    )
    return published
