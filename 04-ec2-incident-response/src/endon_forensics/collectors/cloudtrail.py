"""Collect CloudTrail events involving the instance — the attacker's API trail."""

from __future__ import annotations

import contextlib
import json
from datetime import timedelta

from endon_core.timeutil import utc_now
from endon_forensics.collectors.base import Collector, CollectorContext
from endon_forensics.models import EvidenceItem, EvidenceStatus

LOOKBACK_HOURS = 24


class CloudTrailCollector(Collector):
    id = "cloudtrail-events"
    kind = "log"
    order = 40

    def collect(self, ctx: CollectorContext) -> list[EvidenceItem]:
        cloudtrail = ctx.clients("cloudtrail")
        end = utc_now()
        start = end - timedelta(hours=LOOKBACK_HOURS)
        try:
            events = _lookup(cloudtrail, ctx.case.instance_id, start, end)
        except Exception as exc:  # non-critical evidence: degrade to SKIPPED rather than abort
            return [
                EvidenceItem(
                    id=self.id,
                    kind=self.kind,
                    description="CloudTrail events referencing the instance",
                    status=EvidenceStatus.SKIPPED,
                    collector=self.id,
                    detail={"reason": f"CloudTrail lookup unavailable: {type(exc).__name__}"},
                )
            ]

        record = {
            "instanceId": ctx.case.instance_id,
            "window": {"start": start.isoformat(), "end": end.isoformat(), "hours": LOOKBACK_HOURS},
            "eventCount": len(events),
            "events": events,
        }
        stored = ctx.store.put_json(ctx.case.case_id, "cloudtrail-events.json", record)
        return [
            EvidenceItem(
                id=self.id,
                kind=self.kind,
                description=f"CloudTrail events referencing the instance in the last {LOOKBACK_HOURS}h",
                status=EvidenceStatus.COLLECTED,
                collector=self.id,
                s3_key=stored.key,
                sha256=stored.sha256,
                size_bytes=stored.size_bytes,
                detail={"eventCount": len(events)},
            )
        ]


def _lookup(cloudtrail, instance_id: str, start, end) -> list[dict]:
    events: list[dict] = []
    paginator = cloudtrail.get_paginator("lookup_events")
    for page in paginator.paginate(
        LookupAttributes=[{"AttributeKey": "ResourceName", "AttributeValue": instance_id}],
        StartTime=start,
        EndTime=end,
    ):
        events.extend(_normalize(e) for e in page.get("Events", []))
    return events


def _normalize(event: dict) -> dict:
    # CloudTrailEvent is a JSON string; parse it so the evidence is queryable.
    parsed = event.get("CloudTrailEvent")
    if isinstance(parsed, str):
        with contextlib.suppress(ValueError):
            event = {**event, "CloudTrailEvent": json.loads(parsed)}
    return event
