"""The forensic case model: what was collected, its integrity, and the chain of custody."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import asdict, dataclass, field
from enum import StrEnum
from typing import Any

from endon_core.incidents import TimelineEntry
from endon_core.timeutil import isoformat, utc_now

MANIFEST_SCHEMA = "endon.forensics.manifest/1"


class EvidenceStatus(StrEnum):
    COLLECTED = "COLLECTED"
    SKIPPED = "SKIPPED"  # not applicable or not collectable (with a reason)
    FAILED = "FAILED"


class CaseStatus(StrEnum):
    COLLECTED = "COLLECTED"  # every critical collector succeeded
    PARTIAL = "PARTIAL"  # some evidence collected, at least one critical item missing
    FAILED = "FAILED"  # no evidence could be collected
    SKIPPED = "SKIPPED"  # a case already exists for this incident (idempotent re-delivery)


@dataclass
class EvidenceItem:
    id: str
    kind: str  # metadata | volatile | console | log | disk-snapshot
    description: str
    status: EvidenceStatus
    collector: str
    collected_at: str = field(default_factory=lambda: isoformat(utc_now()))
    s3_key: str | None = None
    sha256: str | None = None
    size_bytes: int | None = None
    detail: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.status = EvidenceStatus(self.status)

    @property
    def collected(self) -> bool:
        return self.status is EvidenceStatus.COLLECTED

    def to_dict(self) -> dict[str, Any]:
        return {**asdict(self), "status": self.status.value}


@dataclass
class ForensicCase:
    case_id: str
    incident_id: str
    instance_id: str
    instance_arn: str
    account_id: str
    region: str
    finding_id: str = ""
    finding_type: str = ""
    severity: str = ""
    collector_identity: str = ""
    opened_at: str = field(default_factory=lambda: isoformat(utc_now()))
    completed_at: str | None = None
    status: CaseStatus = CaseStatus.PARTIAL
    isolation: dict[str, Any] = field(default_factory=dict)
    evidence: list[EvidenceItem] = field(default_factory=list)
    timeline: list[TimelineEntry] = field(default_factory=list)
    manifest_key: str | None = None
    manifest_sha256: str | None = None

    def __post_init__(self) -> None:
        self.status = CaseStatus(self.status)
        self.evidence = [
            e if isinstance(e, EvidenceItem) else EvidenceItem(**e) for e in self.evidence
        ]
        self.timeline = [
            t if isinstance(t, TimelineEntry) else TimelineEntry(**t) for t in self.timeline
        ]

    @classmethod
    def from_request(cls, detail: Mapping[str, Any]) -> ForensicCase:
        incident_id = detail["incidentId"]
        return cls(
            case_id=incident_id,  # one case per incident
            incident_id=incident_id,
            instance_id=detail["instanceId"],
            instance_arn=detail.get("instanceArn", ""),
            account_id=detail["accountId"],
            region=detail["region"],
            finding_id=detail.get("findingId", ""),
            finding_type=detail.get("findingType", ""),
            severity=detail.get("severity", ""),
        )

    def log(self, event: str, detail: str = "", at: str | None = None) -> None:
        self.timeline.append(TimelineEntry(at or isoformat(utc_now()), event, detail))

    def add(self, item: EvidenceItem) -> None:
        self.evidence.append(item)

    @property
    def snapshot_ids(self) -> list[str]:
        return [
            e.detail["snapshotId"]
            for e in self.evidence
            if e.kind == "disk-snapshot" and e.collected and "snapshotId" in e.detail
        ]

    def collected_kinds(self) -> set[str]:
        return {e.kind for e in self.evidence if e.collected}

    def manifest(self) -> dict[str, Any]:
        """The chain-of-custody document — evidence hashes, timestamps and custody metadata."""
        return {
            "schema": MANIFEST_SCHEMA,
            "case_id": self.case_id,
            "incident_id": self.incident_id,
            "status": self.status.value,
            "instance": {"id": self.instance_id, "arn": self.instance_arn},
            "finding": {
                "id": self.finding_id,
                "type": self.finding_type,
                "severity": self.severity,
            },
            "account_id": self.account_id,
            "region": self.region,
            "collector_identity": self.collector_identity,
            "opened_at": self.opened_at,
            "completed_at": self.completed_at,
            "isolation": self.isolation,
            "evidence": [e.to_dict() for e in self.evidence],
            "timeline": [asdict(t) for t in self.timeline],
            "integrity_note": (
                "Each artifact's sha256 is recorded at collection time. Artifacts are stored in "
                "an S3 bucket with Object Lock (WORM), versioning and KMS encryption, so they "
                "cannot be altered or deleted within the retention period."
            ),
        }

    def to_dict(self) -> dict[str, Any]:
        data = self.manifest()
        data["manifest_key"] = self.manifest_key
        data["manifest_sha256"] = self.manifest_sha256
        return data
