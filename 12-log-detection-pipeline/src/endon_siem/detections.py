"""The detection catalog: single-event signatures and windowed correlations.

Two kinds of rule. A **single-event** rule matches one CloudTrail record — root usage, a
stopped trail, a bucket made public. A **correlation** rule slides a time window over one
principal's activity — a burst of GetObject (exfiltration), repeated failed logins (brute
force), a scan of Describe/List calls (reconnaissance), the same credentials from two IPs.
Correlation is where a SIEM earns its keep: the individual calls are unremarkable; the
*pattern* is the attack.

Each detection carries a MITRE ATT&CK technique, so a finding says not just what fired but what
the adversary was doing.
"""

from __future__ import annotations

from collections import deque
from collections.abc import Callable
from dataclasses import dataclass

from endon_core.findings import Domain, Severity
from endon_siem.events import Event

# Source IPs CloudTrail uses for AWS-internal / service calls — not a human's location.
_SERVICE_IPS = {"", "AWS Internal"}


@dataclass(frozen=True)
class Detection:
    id: str
    title: str
    severity: Severity
    domain: Domain
    technique: str  # MITRE ATT&CK id
    kind: str  # "event" | "correlation"
    remediation: str

    @property
    def finding_type(self) -> str:
        return f"Detection:CloudTrail/{self.id}"


# ---- Single-event predicates ------------------------------------------------------
def _root_activity(e: Event) -> bool:
    return e.identity_type == "Root"


def _trail_tampering(e: Event) -> bool:
    return e.source == "cloudtrail.amazonaws.com" and e.name in {"StopLogging", "DeleteTrail"}


def _detection_disabled(e: Event) -> bool:
    return e.name in {
        "DeleteDetector",
        "StopConfigurationRecorder",
        "DisableSecurityHub",
        "DeleteConfigurationRecorder",
    }


def _access_key_created(e: Event) -> bool:
    return e.name == "CreateAccessKey" and not e.failed


def _admin_policy_attached(e: Event) -> bool:
    if e.name not in {"AttachUserPolicy", "AttachRolePolicy"}:
        return False
    return "AdministratorAccess" in str(e.request_parameters.get("policyArn", ""))


def _bucket_made_public(e: Event) -> bool:
    if e.name == "PutBucketPolicy":
        return '"*"' in str(e.request_parameters.get("bucketPolicy", "")) or "Principal" in str(
            e.request_parameters
        )
    if e.name == "PutBucketAcl":
        grants = str(e.request_parameters)
        return "AllUsers" in grants or "public-read" in grants
    return False


def _sg_opened(e: Event) -> bool:
    return e.name == "AuthorizeSecurityGroupIngress" and "0.0.0.0/0" in str(e.request_parameters)


# ---- Correlation helpers ----------------------------------------------------------
def _window_hit(
    events: list[Event],
    match: Callable[[Event], bool],
    count: int,
    seconds: float,
    key: Callable[[Event], str] | None = None,
) -> list[Event] | None:
    """Return the events of the first sliding window (<= `seconds`) with `count` matches."""
    window: deque[Event] = deque()
    for event in (e for e in events if match(e)):
        window.append(event)
        while (event.time - window[0].time).total_seconds() > seconds:
            window.popleft()
        seen = len({key(e) for e in window}) if key else len(window)
        if seen >= count:
            return list(window)
    return None


def _mass_download(events: list[Event]) -> list[Event] | None:
    return _window_hit(events, lambda e: e.name == "GetObject", count=5, seconds=300)


def _brute_force(events: list[Event]) -> list[Event] | None:
    return _window_hit(
        events, lambda e: e.name == "ConsoleLogin" and e.failed, count=4, seconds=300
    )


def _recon_burst(events: list[Event]) -> list[Event] | None:
    def is_read(e: Event) -> bool:
        return e.name.startswith(("Describe", "List")) or (
            e.name.startswith("Get") and e.source != "s3.amazonaws.com"
        )

    return _window_hit(events, is_read, count=8, seconds=300, key=lambda e: e.name)


def _multi_ip(events: list[Event]) -> list[Event] | None:
    return _window_hit(
        events,
        lambda e: e.source_ip not in _SERVICE_IPS and not e.source_ip.endswith(".amazonaws.com"),
        count=2,
        seconds=600,
        key=lambda e: e.source_ip,
    )


SINGLE: dict[str, Callable[[Event], bool]] = {
    "SIEM-001": _root_activity,
    "SIEM-002": _trail_tampering,
    "SIEM-003": _detection_disabled,
    "SIEM-004": _access_key_created,
    "SIEM-005": _admin_policy_attached,
    "SIEM-006": _bucket_made_public,
    "SIEM-007": _sg_opened,
}

CORRELATION: dict[str, Callable[[list[Event]], list[Event] | None]] = {
    "SIEM-101": _mass_download,
    "SIEM-102": _brute_force,
    "SIEM-103": _recon_burst,
    "SIEM-104": _multi_ip,
}

_ALL = [
    Detection(
        "SIEM-001",
        "Root account activity",
        Severity.CRITICAL,
        Domain.INCIDENT_RESPONSE,
        "T1078.004",
        "event",
        "Root should never be used for API calls; investigate and rotate root credentials.",
    ),
    Detection(
        "SIEM-002",
        "CloudTrail logging tampered",
        Severity.HIGH,
        Domain.DETECTION,
        "T1562.008",
        "event",
        "Re-enable the trail and alert; log tampering precedes most attacks.",
    ),
    Detection(
        "SIEM-003",
        "Detective service disabled",
        Severity.HIGH,
        Domain.DETECTION,
        "T1562.001",
        "event",
        "Re-enable GuardDuty/Config/Security Hub and investigate who disabled it.",
    ),
    Detection(
        "SIEM-004",
        "New access key created",
        Severity.MEDIUM,
        Domain.IAM,
        "T1098.001",
        "event",
        "Confirm the key was expected; attackers create keys for persistence.",
    ),
    Detection(
        "SIEM-005",
        "Administrator policy attached",
        Severity.HIGH,
        Domain.IAM,
        "T1098",
        "event",
        "Confirm the grant; attaching AdministratorAccess is a common escalation step.",
    ),
    Detection(
        "SIEM-006",
        "S3 bucket made public",
        Severity.HIGH,
        Domain.DATA_PROTECTION,
        "T1530",
        "event",
        "Re-enable Block Public Access; a public bucket is a data-exposure path.",
    ),
    Detection(
        "SIEM-007",
        "Security group opened to the internet",
        Severity.MEDIUM,
        Domain.INFRASTRUCTURE,
        "T1562.007",
        "event",
        "Scope the ingress rule; 0.0.0.0/0 is an entry point.",
    ),
    Detection(
        "SIEM-101",
        "Mass S3 download (possible exfiltration)",
        Severity.HIGH,
        Domain.DATA_PROTECTION,
        "T1530",
        "correlation",
        "Investigate the principal; a burst of GetObject is exfiltration until proven otherwise.",
    ),
    Detection(
        "SIEM-102",
        "Console login brute force",
        Severity.HIGH,
        Domain.INCIDENT_RESPONSE,
        "T1110",
        "correlation",
        "Lock the account and require MFA; repeated failed logins are a brute-force attempt.",
    ),
    Detection(
        "SIEM-103",
        "Reconnaissance burst",
        Severity.MEDIUM,
        Domain.DETECTION,
        "T1580",
        "correlation",
        "A scan of Describe/List calls maps the account; correlate with the principal's other activity.",
    ),
    Detection(
        "SIEM-104",
        "Credentials used from multiple IPs",
        Severity.HIGH,
        Domain.INCIDENT_RESPONSE,
        "T1078",
        "correlation",
        "The same credentials from two IPs in a short window suggests theft; revoke and rotate.",
    ),
]

BY_ID: dict[str, Detection] = {d.id: d for d in _ALL}


def all_detections() -> list[Detection]:
    return list(_ALL)


def get(detection_id: str) -> Detection:
    return BY_ID[detection_id]
