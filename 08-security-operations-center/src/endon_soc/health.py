"""Detective-control health: is the platform's own vision actually switched on?

A security score built only from findings has a blind spot of its own: if GuardDuty is off,
there are no GuardDuty findings, and the board looks *green* precisely when it is most wrong.
So the SOC checks the detectors themselves — GuardDuty, Security Hub, CloudTrail, AWS Config —
and feeds the count of disabled ones back into the score as a blind-spot penalty.

Each probe is read-only and fails safe: if a call errors (permissions, an unsupported region,
moto offline), the service is reported ``UNKNOWN`` rather than falsely ``ACTIVE``. An unknown
detector is treated as a blind spot for scoring, because you cannot claim coverage you cannot
confirm.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from enum import StrEnum

from endon_core.aws import ClientFactory, error_code


class HealthStatus(StrEnum):
    ACTIVE = "ACTIVE"
    INACTIVE = "INACTIVE"
    UNKNOWN = "UNKNOWN"


@dataclass(frozen=True)
class ServiceHealth:
    name: str
    status: HealthStatus
    detail: str = ""

    @property
    def is_covered(self) -> bool:
        """Only a confirmed ACTIVE counts as coverage; INACTIVE and UNKNOWN are blind spots."""
        return self.status is HealthStatus.ACTIVE

    def to_dict(self) -> dict[str, str]:
        return {"name": self.name, "status": self.status.value, "detail": self.detail}


def _guardduty(clients: ClientFactory) -> ServiceHealth:
    detectors = clients("guardduty").list_detectors().get("DetectorIds", [])
    if not detectors:
        return ServiceHealth("GuardDuty", HealthStatus.INACTIVE, "No detector in this region")
    return ServiceHealth("GuardDuty", HealthStatus.ACTIVE, f"{len(detectors)} detector(s)")


def _security_hub(clients: ClientFactory) -> ServiceHealth:
    clients("securityhub").describe_hub()  # raises if the hub is not enabled
    return ServiceHealth("Security Hub", HealthStatus.ACTIVE, "Hub enabled")


def _cloudtrail(clients: ClientFactory) -> ServiceHealth:
    ct = clients("cloudtrail")
    trails = ct.describe_trails().get("trailList", [])
    for trail in trails:
        name = trail.get("TrailARN") or trail.get("Name")
        status = ct.get_trail_status(Name=name)
        if status.get("IsLogging"):
            return ServiceHealth("CloudTrail", HealthStatus.ACTIVE, f"{trail.get('Name')} logging")
    return ServiceHealth("CloudTrail", HealthStatus.INACTIVE, "No trail is logging")


def _config(clients: ClientFactory) -> ServiceHealth:
    statuses = (
        clients("config")
        .describe_configuration_recorder_status()
        .get("ConfigurationRecordersStatus", [])
    )
    if any(s.get("recording") for s in statuses):
        return ServiceHealth("AWS Config", HealthStatus.ACTIVE, "Recorder on")
    return ServiceHealth("AWS Config", HealthStatus.INACTIVE, "No recorder is recording")


# The detective controls the SOC expects to be on, in display order.
PROBES: tuple[tuple[str, Callable[[ClientFactory], ServiceHealth]], ...] = (
    ("GuardDuty", _guardduty),
    ("Security Hub", _security_hub),
    ("CloudTrail", _cloudtrail),
    ("AWS Config", _config),
)


def probe_detective_services(clients: ClientFactory) -> list[ServiceHealth]:
    """Check every detective control, degrading to UNKNOWN on any error (never a false ACTIVE)."""
    results: list[ServiceHealth] = []
    for name, probe in PROBES:
        try:
            results.append(probe(clients))
        except Exception as exc:  # fail safe: an unconfirmed detector is not coverage
            results.append(ServiceHealth(name, HealthStatus.UNKNOWN, _reason(exc)))
    return results


def blind_service_count(services: list[ServiceHealth]) -> int:
    """How many expected detectors are not confirmed active (INACTIVE or UNKNOWN)."""
    return sum(1 for s in services if not s.is_covered)


def _reason(exc: Exception) -> str:
    return error_code(exc) or type(exc).__name__
