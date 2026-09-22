"""The IaC control catalog: every insecure Terraform pattern the scanner knows.

Each control has a stable ID, a severity, the Endon finding type it produces, and
remediation guidance — the single source of truth for what a control *means*, separate from
how it is detected (that lives in ``rules.py``). Finding types follow
``IaC:<Service>/<Name>`` so a Terraform finding rides the same bus, stores and reports as
every other Endon finding.
"""

from __future__ import annotations

from dataclasses import dataclass

from endon_core.findings import Domain, Severity


@dataclass(frozen=True)
class Control:
    id: str
    service: str
    title: str
    severity: Severity
    finding_type: str
    domain: Domain
    remediation: str


def _c(
    control_id: str,
    service: str,
    name: str,
    title: str,
    severity: Severity,
    domain: Domain,
    remediation: str,
) -> Control:
    return Control(
        id=control_id,
        service=service,
        title=title,
        severity=severity,
        finding_type=f"IaC:{service}/{name}",
        domain=domain,
        remediation=remediation,
    )


_ALL = [
    _c(
        "TF-S3-001",
        "S3",
        "BucketPubliclyAccessible",
        "S3 bucket is exposed publicly",
        Severity.CRITICAL,
        Domain.DATA_PROTECTION,
        "Set the ACL to private and enable a Block Public Access block with all four flags true.",
    ),
    _c(
        "TF-S3-002",
        "S3",
        "BucketEncryptionDisabled",
        "S3 bucket has no server-side encryption",
        Severity.HIGH,
        Domain.DATA_PROTECTION,
        "Add a server_side_encryption_configuration (aws:kms or AES256).",
    ),
    _c(
        "TF-S3-003",
        "S3",
        "BucketVersioningDisabled",
        "S3 bucket versioning is disabled",
        Severity.MEDIUM,
        Domain.DATA_PROTECTION,
        "Enable versioning so objects can be recovered after deletion or overwrite.",
    ),
    _c(
        "TF-EC2-001",
        "EC2",
        "UnrestrictedAdminPort",
        "Security group opens SSH/RDP to the internet",
        Severity.HIGH,
        Domain.INFRASTRUCTURE,
        "Restrict ingress on 22/3389 to known CIDRs or a bastion, never 0.0.0.0/0.",
    ),
    _c(
        "TF-EC2-002",
        "EC2",
        "UnrestrictedIngress",
        "Security group allows ingress from 0.0.0.0/0",
        Severity.MEDIUM,
        Domain.INFRASTRUCTURE,
        "Scope ingress CIDRs to what actually needs access.",
    ),
    _c(
        "TF-EC2-003",
        "EC2",
        "Imdsv2NotEnforced",
        "EC2 instance does not enforce IMDSv2",
        Severity.MEDIUM,
        Domain.INFRASTRUCTURE,
        'Set metadata_options.http_tokens = "required" to block SSRF credential theft.',
    ),
    _c(
        "TF-EBS-001",
        "EBS",
        "VolumeNotEncrypted",
        "EBS volume is not encrypted at rest",
        Severity.HIGH,
        Domain.DATA_PROTECTION,
        "Set encrypted = true (ideally with a customer-managed KMS key).",
    ),
    _c(
        "TF-RDS-001",
        "RDS",
        "InstanceNotEncrypted",
        "RDS instance storage is not encrypted",
        Severity.HIGH,
        Domain.DATA_PROTECTION,
        "Set storage_encrypted = true with a KMS key.",
    ),
    _c(
        "TF-RDS-002",
        "RDS",
        "InstancePubliclyAccessible",
        "RDS instance is publicly accessible",
        Severity.CRITICAL,
        Domain.INFRASTRUCTURE,
        "Set publicly_accessible = false and place the instance in private subnets.",
    ),
    _c(
        "TF-IAM-001",
        "IAM",
        "AdministratorPolicy",
        "IAM policy grants administrator-equivalent access",
        Severity.CRITICAL,
        Domain.IAM,
        'Replace Action "*" on Resource "*" with the specific actions the workload needs.',
    ),
    _c(
        "TF-IAM-002",
        "IAM",
        "UnscopedPassRole",
        "IAM policy allows iam:PassRole on any role",
        Severity.HIGH,
        Domain.IAM,
        "Scope iam:PassRole to specific role ARNs; a wildcard is a privilege-escalation path.",
    ),
    _c(
        "TF-KMS-001",
        "KMS",
        "KeyRotationDisabled",
        "KMS key does not have rotation enabled",
        Severity.MEDIUM,
        Domain.DATA_PROTECTION,
        "Set enable_key_rotation = true on customer-managed keys.",
    ),
    _c(
        "TF-LOG-001",
        "CloudTrail",
        "TrailNotHardened",
        "CloudTrail is single-region or unencrypted",
        Severity.HIGH,
        Domain.DETECTION,
        "Set is_multi_region_trail = true and a kms_key_id so the audit log is complete and encrypted.",
    ),
]

BY_ID: dict[str, Control] = {c.id: c for c in _ALL}


def all_controls() -> list[Control]:
    return list(_ALL)


def get(control_id: str) -> Control:
    return BY_ID[control_id]
