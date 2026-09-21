"""The SOC read-model over the platform's stores."""

from endon_core.findings import Severity
from endon_core.incidents import IncidentStatus
from endon_soc.health import HealthStatus, ServiceHealth
from endon_soc.service import SocService


def test_summary_aggregates_findings_incidents_and_health(demo_service):
    summary = demo_service.summary()
    assert summary.total_findings == 6
    assert summary.total_incidents == 3
    assert summary.severity_counts["CRITICAL"] == 1
    assert summary.severity_counts["HIGH"] == 2
    # Score is derived, grade follows the score.
    assert 0 <= summary.security_score <= 100
    assert summary.grade in {"A", "B", "C", "D", "F"}


def test_blind_detectors_lower_the_summary_score(demo_service):
    incidents, findings = demo_service._incidents, demo_service._findings
    lit = SocService(
        incidents, findings, health=[ServiceHealth("GuardDuty", HealthStatus.ACTIVE)]
    ).summary()
    blind = SocService(
        incidents, findings, health=[ServiceHealth("GuardDuty", HealthStatus.INACTIVE)]
    ).summary()
    assert blind.security_score < lit.security_score


def test_incidents_can_be_filtered_by_status(demo_service):
    monitoring = demo_service.incidents(status="MONITORING")
    assert monitoring and all(i.status is IncidentStatus.MONITORING for i in monitoring)
    contained = demo_service.incidents(status="CONTAINED")
    assert len(contained) == 2


def test_findings_filter_by_severity_floor_and_source(demo_service):
    highs = demo_service.findings(severity="HIGH")
    assert highs and all(f.severity.at_least(Severity.HIGH) for f in highs)
    assert all(f.severity.value in {"HIGH", "CRITICAL"} for f in highs)

    iam = demo_service.findings(source="endon.iam-analyzer")
    assert iam and all(f.source == "endon.iam-analyzer" for f in iam)


def test_get_incident_returns_full_record_or_none(demo_service):
    first = demo_service.incidents()[0]
    fetched = demo_service.incident(first.incident_id)
    assert fetched is not None
    assert fetched.timeline  # the full timeline is present
    assert demo_service.incident("INC-DOESNOTEXIST") is None
