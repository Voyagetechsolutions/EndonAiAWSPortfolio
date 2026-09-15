"""CloudTrail posture: coverage, log integrity, encryption, logging state."""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any

from endon_core.findings import Finding, Resource
from endon_posture.checks.base import check
from endon_posture.context import ScanContext


@check("CloudTrail")
def cloudtrail(ctx: ScanContext) -> Iterator[Finding]:
    client = ctx.clients("cloudtrail")
    trails = client.describe_trails(includeShadowTrails=False).get("trailList", [])

    if not any(t.get("IsMultiRegionTrail") for t in trails):
        yield ctx.finding("CT-001", ctx.account_resource())

    for trail in trails:
        # Only evaluate a trail in its home region, so a multi-region trail is judged once.
        if trail.get("HomeRegion") not in (None, ctx.region):
            continue
        resource = Resource(
            "AwsCloudTrailTrail",
            trail.get("TrailARN", ""),
            region=ctx.region,
            details={"name": trail.get("Name")},
        )
        if not trail.get("LogFileValidationEnabled"):
            yield ctx.finding("CT-002", resource)
        if not trail.get("KmsKeyId"):
            yield ctx.finding("CT-003", resource)
        if not _is_logging(client, trail):
            yield ctx.finding("CT-004", resource)


def _is_logging(client: Any, trail: dict[str, Any]) -> bool:
    try:
        return bool(client.get_trail_status(Name=trail["TrailARN"]).get("IsLogging"))
    except Exception:
        return True  # cannot determine; do not raise a false "not logging"
