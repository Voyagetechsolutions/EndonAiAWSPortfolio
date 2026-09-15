"""Incident record produced by the response engine: what happened, what was done, and when."""

from __future__ import annotations

import hashlib
from dataclasses import asdict, dataclass, field
from enum import StrEnum
from typing import Any

from endon_core.findings import Finding
from endon_core.timeutil import isoformat, seconds_between, utc_now


class IncidentStatus(StrEnum):
    OPEN = "OPEN"
    CONTAINED = "CONTAINED"
    PARTIALLY_CONTAINED = "PARTIALLY_CONTAINED"
    FAILED = "FAILED"
    SUPPRESSED = "SUPPRESSED"  # a guardrail blocked containment; a human must decide
    MONITORING = "MONITORING"  # no containment was warranted; recorded and reported
    DRY_RUN = "DRY_RUN"


class ActionKind(StrEnum):
    CONTAIN = "CONTAIN"  # disruptive (disable keys, isolate hosts): severity-gated and guardrailed
    REMEDIATE = "REMEDIATE"  # reverses an attacker's change (re-enable logging): guardrailed
    EVIDENCE = "EVIDENCE"  # tagging and forensic evidence requests
    REPORT = "REPORT"  # notifications; always run last so they report the final outcome


class ActionStatus(StrEnum):
    SUCCEEDED = "SUCCEEDED"
    FAILED = "FAILED"
    SKIPPED = "SKIPPED"
    SUPPRESSED = "SUPPRESSED"
    DRY_RUN = "DRY_RUN"


@dataclass
class TimelineEntry:
    at: str
    event: str
    detail: str = ""


@dataclass
class ActionRecord:
    action: str
    kind: ActionKind
    target: str
    status: ActionStatus
    message: str = ""
    at: str = field(default_factory=lambda: isoformat(utc_now()))
    data: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.kind = ActionKind(self.kind)
        self.status = ActionStatus(self.status)


@dataclass
class Incident:
    incident_id: str
    finding: Finding
    playbook: str
    opened_at: str
    detected_at: str
    status: IncidentStatus = IncidentStatus.OPEN
    contained_at: str | None = None
    occurrences: int = 1
    actions: list[ActionRecord] = field(default_factory=list)
    timeline: list[TimelineEntry] = field(default_factory=list)

    def __post_init__(self) -> None:
        if isinstance(self.finding, dict):
            self.finding = Finding.from_dict(self.finding)
        self.status = IncidentStatus(self.status)
        self.actions = [
            a if isinstance(a, ActionRecord) else ActionRecord(**a) for a in self.actions
        ]
        self.timeline = [
            t if isinstance(t, TimelineEntry) else TimelineEntry(**t) for t in self.timeline
        ]

    @staticmethod
    def id_for(finding: Finding) -> str:
        """Deterministic id, so a re-delivered finding maps to the same incident."""
        return "INC-" + hashlib.sha256(finding.id.encode()).hexdigest()[:12].upper()

    @classmethod
    def open(cls, finding: Finding, playbook: str, opened_at: str) -> Incident:
        return cls(
            incident_id=cls.id_for(finding),
            finding=finding,
            playbook=playbook,
            opened_at=opened_at,
            detected_at=finding.first_observed_at or finding.created_at,
        )

    def log(self, event: str, detail: str = "", at: str | None = None) -> None:
        self.timeline.append(TimelineEntry(at or isoformat(utc_now()), event, detail))

    @property
    def time_to_contain_seconds(self) -> float | None:
        if not self.contained_at:
            return None
        return max(0.0, seconds_between(self.detected_at, self.contained_at))

    def to_dict(self, include_raw: bool = True) -> dict[str, Any]:
        return {
            "incident_id": self.incident_id,
            "finding": self.finding.to_dict(include_raw=include_raw),
            "playbook": self.playbook,
            "opened_at": self.opened_at,
            "detected_at": self.detected_at,
            "status": self.status.value,
            "contained_at": self.contained_at,
            "occurrences": self.occurrences,
            "actions": [
                {**asdict(a), "kind": a.kind.value, "status": a.status.value} for a in self.actions
            ],
            "timeline": [asdict(t) for t in self.timeline],
            "time_to_contain_seconds": self.time_to_contain_seconds,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Incident:
        data = {k: v for k, v in data.items() if k != "time_to_contain_seconds"}
        return cls(**data)
