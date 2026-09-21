"""The SOC read-model: turns the platform's incident and finding stores into one view.

This is deliberately read-only. The SOC observes the platform; it never contains, remediates,
or writes back. That boundary is a security property, not just tidiness — a dashboard that
could act is a dashboard an attacker who reaches it could act *through*. The stores are the
same ``endon_core`` contracts every other component writes, so the SOC shows the real output
of Projects 1-5 with no bespoke schema.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from endon_core.findings import Finding, Severity
from endon_core.incidents import Incident, IncidentStatus
from endon_core.store import FindingStore, IncidentStore
from endon_core.timeutil import isoformat, utc_now
from endon_soc.health import ServiceHealth, blind_service_count
from endon_soc.score import SeverityTally, security_score


@dataclass(frozen=True)
class SocSummary:
    """Everything the top of the board shows, computed once from the stores."""

    generated_at: str
    security_score: int
    grade: str
    severity_counts: dict[str, int]
    incident_status_counts: dict[str, int]
    total_findings: int
    total_incidents: int
    open_incidents: int
    services: list[ServiceHealth]
    score_breakdown: dict[str, Any]

    @property
    def severity_tally(self) -> SeverityTally:
        return SeverityTally.from_counts(self.severity_counts)

    def to_dict(self) -> dict[str, Any]:
        return {
            "generated_at": self.generated_at,
            "security_score": self.security_score,
            "grade": self.grade,
            "severity_counts": self.severity_counts,
            "incident_status_counts": self.incident_status_counts,
            "total_findings": self.total_findings,
            "total_incidents": self.total_incidents,
            "open_incidents": self.open_incidents,
            "services": [s.to_dict() for s in self.services],
            "score_breakdown": self.score_breakdown,
        }


# Incident statuses that still need a human's attention (not yet resolved by automation).
_OPEN_STATUSES = frozenset(
    {
        IncidentStatus.OPEN,
        IncidentStatus.PARTIALLY_CONTAINED,
        IncidentStatus.FAILED,
        IncidentStatus.SUPPRESSED,
        IncidentStatus.MONITORING,
    }
)


class SocService:
    def __init__(
        self,
        incidents: IncidentStore,
        findings: FindingStore,
        health: list[ServiceHealth] | None = None,
    ) -> None:
        self._incidents = incidents
        self._findings = findings
        self._health = health or []

    def summary(self, limit: int = 1000) -> SocSummary:
        findings = self._findings.list(limit=limit)
        incidents = self._incidents.list(limit=limit)
        blind = blind_service_count(self._health)
        breakdown = security_score(findings, blind_services=blind)

        status_counts: dict[str, int] = {status.value: 0 for status in IncidentStatus}
        for incident in incidents:
            status_counts[incident.status.value] += 1
        open_incidents = sum(1 for i in incidents if i.status in _OPEN_STATUSES)

        return SocSummary(
            generated_at=isoformat(utc_now()),
            security_score=breakdown.score,
            grade=breakdown.grade,
            severity_counts=breakdown.severity_counts,
            incident_status_counts=status_counts,
            total_findings=len(findings),
            total_incidents=len(incidents),
            open_incidents=open_incidents,
            services=self._health,
            score_breakdown=breakdown.to_dict(),
        )

    def incidents(self, status: str | None = None, limit: int = 100) -> list[Incident]:
        items = self._incidents.list(limit=limit)
        if status:
            wanted = IncidentStatus(status.upper())
            items = [i for i in items if i.status is wanted]
        return items

    def incident(self, incident_id: str) -> Incident | None:
        return self._incidents.get(incident_id)

    def findings(
        self, severity: str | None = None, source: str | None = None, limit: int = 100
    ) -> list[Finding]:
        items = self._findings.list(limit=limit)
        if severity:
            floor = Severity(severity.upper())
            items = [f for f in items if f.severity.at_least(floor)]
        if source:
            items = [f for f in items if f.source == source]
        return items
