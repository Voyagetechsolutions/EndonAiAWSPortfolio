"""Normalized security finding shared by every Endon AI component.

Producers (GuardDuty and Security Hub normalizers, the IAM analyzer, the posture
scanner, the data protection monitor) emit a ``Finding``. Consumers (the response
engine, forensics, the SOC dashboard) read one. The model maps directly onto the
AWS Security Finding Format (ASFF) so any finding can be imported into Security Hub.

Finding type naming follows GuardDuty's ``Category:Resource/Name`` convention so
native and Endon-generated findings route through the same playbook rules:

* ``UnauthorizedAccess:IAMUser/MaliciousIPCaller``  (GuardDuty)
* ``Posture:S3/BucketPubliclyAccessible``           (posture scanner)
* ``IAM:Role/PrivilegeEscalationPath``              (IAM analyzer)
* ``DataProtection:S3/SensitiveDataExposed``        (data protection monitor)
"""

from __future__ import annotations

import hashlib
from dataclasses import asdict, dataclass, field, fields
from enum import StrEnum
from typing import Any

from endon_core.timeutil import isoformat, utc_now

_NORMALIZED = {"INFORMATIONAL": 0, "LOW": 20, "MEDIUM": 50, "HIGH": 75, "CRITICAL": 95}


class Severity(StrEnum):
    INFORMATIONAL = "INFORMATIONAL"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

    @property
    def rank(self) -> int:
        return list(Severity).index(self)

    @property
    def normalized(self) -> int:
        """ASFF ``Severity.Normalized`` value (0-100)."""
        return _NORMALIZED[self.value]

    def at_least(self, other: Severity) -> bool:
        return self.rank >= other.rank

    @classmethod
    def from_guardduty(cls, score: float) -> Severity:
        """Map a GuardDuty severity score (1.0-10.0) onto a label."""
        if score >= 9.0:
            return cls.CRITICAL
        if score >= 7.0:
            return cls.HIGH
        if score >= 4.0:
            return cls.MEDIUM
        if score >= 1.0:
            return cls.LOW
        return cls.INFORMATIONAL


class Domain(StrEnum):
    """AWS Certified Security - Specialty (SCS-C03) content domains."""

    DETECTION = "Detection"
    INCIDENT_RESPONSE = "Incident Response"
    INFRASTRUCTURE = "Infrastructure Security"
    IAM = "Identity and Access Management"
    DATA_PROTECTION = "Data Protection"
    GOVERNANCE = "Security Foundations and Governance"


@dataclass
class Resource:
    """An AWS resource referenced by a finding. ``type`` uses ASFF resource type names."""

    type: str
    id: str
    region: str | None = None
    details: dict[str, Any] = field(default_factory=dict)

    @property
    def name(self) -> str:
        """Short name derived from the ARN/identifier (user name, bucket name, instance id)."""
        tail = self.id.rsplit("/", 1)[-1]
        return tail.rsplit(":", 1)[-1]


@dataclass
class Finding:
    source: str
    type: str
    title: str
    severity: Severity
    account_id: str
    region: str
    resources: list[Resource] = field(default_factory=list)
    description: str = ""
    remediation: str = ""
    id: str = ""
    created_at: str = field(default_factory=lambda: isoformat(utc_now()))
    updated_at: str = field(default_factory=lambda: isoformat(utc_now()))
    first_observed_at: str | None = None
    control_id: str | None = None
    domain: Domain | None = None
    tags: dict[str, str] = field(default_factory=dict)
    raw: dict[str, Any] = field(default_factory=dict, repr=False)

    def __post_init__(self) -> None:
        self.severity = Severity(self.severity)
        if self.domain is not None:
            self.domain = Domain(self.domain)
        self.resources = [r if isinstance(r, Resource) else Resource(**r) for r in self.resources]
        if not self.id:
            self.id = self.fingerprint()

    def fingerprint(self) -> str:
        """Stable identity: the same issue on the same resources always yields the same id."""
        parts = [self.source, self.type, self.account_id, self.region]
        parts.extend(sorted(r.id for r in self.resources))
        return hashlib.sha256("|".join(parts).encode()).hexdigest()[:32]

    @property
    def is_sample(self) -> bool:
        return self.tags.get("sample") == "true"

    def resources_of(self, resource_type: str) -> list[Resource]:
        return [r for r in self.resources if r.type == resource_type]

    def to_dict(self, include_raw: bool = True) -> dict[str, Any]:
        data = asdict(self)
        data["severity"] = self.severity.value
        data["domain"] = self.domain.value if self.domain else None
        if not include_raw:
            data.pop("raw")
        return data

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Finding:
        known = {f.name for f in fields(cls)}
        return cls(**{k: v for k, v in data.items() if k in known})

    def to_asff(self, product_arn: str) -> dict[str, Any]:
        """Render as an AWS Security Finding Format record for ``BatchImportFindings``."""
        if self.type.startswith("DataProtection:"):
            namespace = "Sensitive Data Identifications"
        elif self.type.startswith(("Posture:", "IAM:")):
            namespace = "Software and Configuration Checks"
        else:
            namespace = "Unusual Behaviors"
        record: dict[str, Any] = {
            "SchemaVersion": "2018-10-08",
            "Id": self.id,
            "ProductArn": product_arn,
            "GeneratorId": self.control_id or self.type,
            "AwsAccountId": self.account_id,
            "Types": [f"{namespace}/Endon AI/{self.type}"],
            "CreatedAt": self.created_at,
            "UpdatedAt": self.updated_at,
            "Severity": {"Label": self.severity.value},
            "Title": self.title[:256],
            "Description": (self.description or self.title)[:1024],
            "Region": self.region,
            "Resources": [
                {"Type": r.type, "Id": r.id, "Region": r.region or self.region}
                for r in self.resources
            ]
            or [{"Type": "AwsAccount", "Id": f"AWS::::Account:{self.account_id}"}],
            "ProductFields": {"endon/source": self.source, "endon/type": self.type},
        }
        if self.first_observed_at:
            record["FirstObservedAt"] = self.first_observed_at
        if self.remediation:
            record["Remediation"] = {"Recommendation": {"Text": self.remediation[:512]}}
        return record
