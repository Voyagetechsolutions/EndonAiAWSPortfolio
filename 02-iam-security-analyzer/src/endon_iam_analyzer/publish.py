"""Publish analyzer findings onto the Endon security bus.

Each finding becomes an ``Endon Finding`` event from source ``endon.iam-analyzer``.
The response engine (Project 1) routes ``IAM:*`` types to its ``iam-risk-review``
playbook, which alerts rather than auto-remediating: removing IAM permissions
automatically would break production.
"""

from __future__ import annotations

from endon_core.events import DetailType, EventPublisher, Source
from endon_core.findings import Finding, Severity
from endon_core.log import get_logger
from endon_iam_analyzer.analyzer import AnalysisResult

logger = get_logger(__name__)


def publish_findings(
    result: AnalysisResult, publisher: EventPublisher, min_severity: Severity = Severity.LOW
) -> int:
    published = 0
    for finding in result.findings:
        if not finding.severity.at_least(min_severity):
            continue
        publisher.publish(
            Source.IAM_ANALYZER,
            DetailType.FINDING,
            {"finding": _publishable(finding).to_dict(include_raw=False)},
            resources=[r.id for r in finding.resources if r.id.startswith("arn:")],
        )
        published += 1
    logger.info("Published IAM findings", extra={"account": result.account_id, "count": published})
    return published


def _publishable(finding: Finding) -> Finding:
    # The event envelope carries the source; keep the finding's own source aligned.
    finding.source = Source.IAM_ANALYZER
    return finding
