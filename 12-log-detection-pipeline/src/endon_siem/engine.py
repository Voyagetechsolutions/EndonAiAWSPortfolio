"""The detection engine: run single-event and correlation rules over a CloudTrail stream.

Single-event rules run per record. Correlation rules run per *principal*: the engine groups the
events by who made them and slides each rule's time window over that principal's timeline. The
output is ``endon_core.Finding`` objects, so a log detection lands in the same SOC, stores and
ASFF as a GuardDuty finding — this is the continuous-monitoring layer under the event-driven
responder (Project 1).
"""

from __future__ import annotations

from collections import defaultdict

from endon_core.findings import Finding, Resource
from endon_siem.detections import CORRELATION, SINGLE, Detection, get
from endon_siem.events import Event, load, load_file

SOURCE = "endon.siem"


def detect(events: list[Event]) -> list[Finding]:
    findings: list[Finding] = []

    for event in events:
        for detection_id, predicate in SINGLE.items():
            if predicate(event):
                findings.append(
                    _finding(get(detection_id), event, f"{event.name} by {event.principal}")
                )

    by_principal: dict[str, list[Event]] = defaultdict(list)
    for event in events:
        by_principal[event.principal].append(event)

    for principal, principal_events in by_principal.items():
        for detection_id, correlation in CORRELATION.items():
            window = correlation(principal_events)
            if window:
                trigger = window[-1]
                detail = f"{len(window)} events for {principal} within the window"
                findings.append(_finding(get(detection_id), trigger, detail))

    findings.sort(key=lambda f: (-f.severity.rank, f.first_observed_at or "", f.type))
    return findings


def detect_records(records: list[dict]) -> list[Finding]:
    return detect(load(records))


def detect_file(path) -> list[Finding]:
    return detect(load_file(path))


def _finding(detection: Detection, event: Event, detail: str) -> Finding:
    return Finding(
        source=SOURCE,
        type=detection.finding_type,
        title=detection.title,
        severity=detection.severity,
        account_id=event.account_id or "unknown",
        region=event.region or "global",
        domain=detection.domain,
        resources=[Resource(type="CloudTrailPrincipal", id=event.principal, region=event.region)],
        description=f"{detection.title} — {detail} (ATT&CK {detection.technique}).",
        remediation=detection.remediation,
        control_id=detection.id,
        first_observed_at=event.raw.get("eventTime")
        or event.time.isoformat().replace("+00:00", "Z"),
        tags={"technique": detection.technique, "source": "cloudtrail"},
    )
