"""The control catalog: every misconfiguration the scanner knows how to find.

Each control has a stable ID (so findings, reports and the benchmark can refer to it),
a severity, the Endon finding type it produces, and remediation guidance. Checks in
``checks/`` reference controls by ID; this module is the single source of truth for what
a control *means*, separate from how it is detected.

Finding types follow ``Posture:<Service>/<Name>`` so they route through the same Endon
bus and playbooks as native findings. ``Posture:S3/BucketPubliclyAccessible`` in
particular is auto-remediated by the Project 1 response engine.
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
    rationale: str
    remediation: str


def _control(
    control_id: str,
    service: str,
    title: str,
    severity: Severity,
    name: str,
    domain: Domain,
    rationale: str,
    remediation: str,
) -> Control:
    return Control(
        id=control_id,
        service=service,
        title=title,
        severity=severity,
        finding_type=f"Posture:{service}/{name}",
        domain=domain,
        rationale=rationale,
        remediation=remediation,
    )


_ALL = [
    # --- S3 ---------------------------------------------------------------------
    _control(
        "S3-001",
        "S3",
        "S3 bucket is publicly accessible",
        Severity.CRITICAL,
        "BucketPubliclyAccessible",
        Domain.DATA_PROTECTION,
        "A bucket ACL or bucket policy grants access to everyone, and Block Public Access "
        "is not fully enabled to neutralize it. Public buckets are a leading cause of data breaches.",
        "Enable all four S3 Block Public Access settings and remove public ACL grants and "
        "wildcard-principal policy statements.",
    ),
    _control(
        "S3-002",
        "S3",
        "S3 Block Public Access is not fully enabled",
        Severity.HIGH,
        "BlockPublicAccessDisabled",
        Domain.DATA_PROTECTION,
        "One or more of the four Block Public Access settings is off, so a future ACL or "
        "policy change could expose the bucket without warning.",
        "Enable BlockPublicAcls, IgnorePublicAcls, BlockPublicPolicy and RestrictPublicBuckets.",
    ),
    _control(
        "S3-003",
        "S3",
        "S3 bucket has no default encryption configured",
        Severity.MEDIUM,
        "BucketEncryptionDisabled",
        Domain.DATA_PROTECTION,
        "The bucket has no default server-side encryption configuration; objects rely on "
        "per-request settings rather than an enforced default.",
        "Set default encryption to SSE-KMS (or at least SSE-S3) on the bucket.",
    ),
    _control(
        "S3-004",
        "S3",
        "S3 bucket does not enforce TLS",
        Severity.MEDIUM,
        "BucketTlsNotEnforced",
        Domain.DATA_PROTECTION,
        "The bucket policy does not deny requests made over plain HTTP "
        "(aws:SecureTransport = false), so data can be read or written in the clear.",
        "Add a bucket policy statement denying s3:* when aws:SecureTransport is false.",
    ),
    _control(
        "S3-005",
        "S3",
        "S3 bucket versioning is disabled",
        Severity.MEDIUM,
        "BucketVersioningDisabled",
        Domain.DATA_PROTECTION,
        "Without versioning, an overwrite or delete (accidental or malicious, e.g. ransomware) "
        "is unrecoverable.",
        "Enable versioning, and consider MFA delete for critical buckets.",
    ),
    _control(
        "S3-006",
        "S3",
        "S3 bucket has no server access logging",
        Severity.LOW,
        "BucketLoggingDisabled",
        Domain.DATA_PROTECTION,
        "Server access logging is off, so reads and writes to the bucket are not recorded.",
        "Enable server access logging to a dedicated log bucket.",
    ),
    # --- EC2 / networking -------------------------------------------------------
    _control(
        "EC2-001",
        "EC2",
        "Security group allows SSH from the internet",
        Severity.HIGH,
        "SshOpenToInternet",
        Domain.INFRASTRUCTURE,
        "A security group allows inbound TCP 22 from 0.0.0.0/0 or ::/0, exposing SSH to the "
        "whole internet for brute forcing and exploitation.",
        "Restrict port 22 to specific admin CIDRs, or use SSM Session Manager instead of SSH.",
    ),
    _control(
        "EC2-002",
        "EC2",
        "Security group allows RDP from the internet",
        Severity.HIGH,
        "RdpOpenToInternet",
        Domain.INFRASTRUCTURE,
        "A security group allows inbound TCP 3389 from 0.0.0.0/0 or ::/0, exposing RDP to the "
        "whole internet.",
        "Restrict port 3389 to specific admin CIDRs, or use SSM Session Manager.",
    ),
    _control(
        "EC2-003",
        "EC2",
        "Security group allows all traffic from the internet",
        Severity.HIGH,
        "AllPortsOpenToInternet",
        Domain.INFRASTRUCTURE,
        "A security group allows all protocols/ports from 0.0.0.0/0, effectively placing the "
        "attached resources directly on the public internet.",
        "Replace the open rule with least-privilege rules scoped to required ports and sources.",
    ),
    _control(
        "EC2-004",
        "EC2",
        "Default security group is not locked down",
        Severity.MEDIUM,
        "DefaultSecurityGroupNotRestricted",
        Domain.INFRASTRUCTURE,
        "The VPC default security group has ingress rules. It should permit no traffic, so that "
        "resources placed in it by mistake are not silently reachable.",
        "Remove all ingress and egress rules from every default security group.",
    ),
    _control(
        "EC2-005",
        "EC2",
        "EBS volume is not encrypted",
        Severity.MEDIUM,
        "EbsVolumeNotEncrypted",
        Domain.DATA_PROTECTION,
        "An EBS volume stores data at rest without encryption.",
        "Recreate the volume from an encrypted snapshot, and enable EBS encryption by default.",
    ),
    _control(
        "EC2-006",
        "EC2",
        "EBS encryption by default is disabled",
        Severity.MEDIUM,
        "EbsDefaultEncryptionDisabled",
        Domain.DATA_PROTECTION,
        "New EBS volumes in this region are created unencrypted unless the caller opts in.",
        "Enable EBS encryption by default for the region.",
    ),
    _control(
        "EC2-007",
        "EC2",
        "EC2 instance does not require IMDSv2",
        Severity.MEDIUM,
        "Imdsv2NotEnforced",
        Domain.INFRASTRUCTURE,
        "The instance metadata service accepts IMDSv1 (HttpTokens != required), which makes "
        "instance-role credential theft via SSRF far easier.",
        "Set MetadataOptions HttpTokens to 'required' to enforce IMDSv2.",
    ),
    # --- RDS --------------------------------------------------------------------
    _control(
        "RDS-001",
        "RDS",
        "RDS instance is publicly accessible",
        Severity.HIGH,
        "InstancePubliclyAccessible",
        Domain.DATA_PROTECTION,
        "The database instance has a public endpoint, exposing it beyond the VPC.",
        "Set PubliclyAccessible to false and reach the database through private networking.",
    ),
    _control(
        "RDS-002",
        "RDS",
        "RDS storage is not encrypted",
        Severity.HIGH,
        "StorageNotEncrypted",
        Domain.DATA_PROTECTION,
        "The database's storage is not encrypted at rest.",
        "Recreate the instance from an encrypted snapshot with StorageEncrypted enabled.",
    ),
    _control(
        "RDS-003",
        "RDS",
        "RDS automated backups are disabled",
        Severity.MEDIUM,
        "BackupsDisabled",
        Domain.DATA_PROTECTION,
        "The backup retention period is 0, so there is no point-in-time recovery.",
        "Set a backup retention period of at least 7 days.",
    ),
    # --- CloudTrail -------------------------------------------------------------
    _control(
        "CT-001",
        "CloudTrail",
        "No multi-region CloudTrail trail is configured",
        Severity.HIGH,
        "NoMultiRegionTrail",
        Domain.GOVERNANCE,
        "There is no multi-region CloudTrail trail, so API activity in some regions is not "
        "recorded. Attackers operate in unused regions precisely because they are unmonitored.",
        "Create an organization or account multi-region trail that logs all management events.",
    ),
    _control(
        "CT-002",
        "CloudTrail",
        "CloudTrail log file validation is disabled",
        Severity.MEDIUM,
        "LogFileValidationDisabled",
        Domain.GOVERNANCE,
        "Without log file validation, tampering with delivered CloudTrail logs cannot be detected.",
        "Enable log file validation on the trail.",
    ),
    _control(
        "CT-003",
        "CloudTrail",
        "CloudTrail logs are not encrypted with KMS",
        Severity.MEDIUM,
        "LogsNotKmsEncrypted",
        Domain.DATA_PROTECTION,
        "The trail does not use an SSE-KMS key, so log access is not gated by a key policy.",
        "Configure the trail with a customer-managed KMS key.",
    ),
    _control(
        "CT-004",
        "CloudTrail",
        "CloudTrail trail is not logging",
        Severity.HIGH,
        "TrailNotLogging",
        Domain.DETECTION,
        "The trail exists but logging is turned off, so no events are being recorded.",
        "Start logging on the trail and alert on StopLogging (Project 1 does this).",
    ),
    # --- KMS --------------------------------------------------------------------
    _control(
        "KMS-001",
        "KMS",
        "KMS key rotation is disabled",
        Severity.MEDIUM,
        "KeyRotationDisabled",
        Domain.DATA_PROTECTION,
        "Automatic annual rotation is off for a customer-managed key, so a compromised key "
        "protects data indefinitely.",
        "Enable automatic key rotation on the customer-managed key.",
    ),
    _control(
        "KMS-002",
        "KMS",
        "KMS key policy allows any principal",
        Severity.HIGH,
        "KeyPolicyWildcardPrincipal",
        Domain.DATA_PROTECTION,
        "The key policy grants use of the key to Principal '*', which can expose encrypted data "
        "to any principal that can reach the key.",
        "Scope the key policy to specific principals; never use Principal '*' without tight conditions.",
    ),
    # --- IAM (account-level posture) -------------------------------------------
    _control(
        "IAM-001",
        "IAM",
        "Account password policy is missing or weak",
        Severity.MEDIUM,
        "WeakPasswordPolicy",
        Domain.IAM,
        "The account has no password policy, or one weaker than a 14-character minimum, so "
        "console passwords may be easy to guess.",
        "Set a password policy requiring at least 14 characters and complexity.",
    ),
    _control(
        "IAM-002",
        "IAM",
        "Root user has active access keys",
        Severity.CRITICAL,
        "RootAccessKeys",
        Domain.IAM,
        "The root user has access keys. Root cannot be constrained by policy, so a leaked root "
        "key is total, unrecoverable account compromise.",
        "Delete all root access keys and operate through IAM roles and users.",
    ),
    _control(
        "IAM-003",
        "IAM",
        "Root user does not have MFA enabled",
        Severity.HIGH,
        "RootMfaDisabled",
        Domain.IAM,
        "MFA is not enabled on the root user, the most privileged identity in the account.",
        "Enable a hardware or virtual MFA device on the root user.",
    ),
    # --- Detective services -----------------------------------------------------
    _control(
        "DET-001",
        "GuardDuty",
        "GuardDuty is not enabled",
        Severity.MEDIUM,
        "GuardDutyDisabled",
        Domain.DETECTION,
        "GuardDuty is not enabled in this region, so there is no managed threat detection "
        "feeding the Endon response engine.",
        "Enable GuardDuty in every region (the Project 6 landing zone does this org-wide).",
    ),
    _control(
        "DET-002",
        "Config",
        "AWS Config is not recording",
        Severity.MEDIUM,
        "ConfigNotRecording",
        Domain.GOVERNANCE,
        "AWS Config has no active recorder, so resource configuration changes are not tracked "
        "and compliance cannot be evaluated over time.",
        "Enable an AWS Config recorder covering all resource types.",
    ),
]

CONTROLS: dict[str, Control] = {control.id: control for control in _ALL}
