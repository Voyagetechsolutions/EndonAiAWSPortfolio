"""Playbooks: which response a finding gets.

Rules are evaluated in order and the first match wins. Two principles shape them:

* Disruptive containment (disabling credentials, isolating hosts) only happens for
  high-confidence compromise indicators from AWS-native detectors. Reconnaissance,
  root activity and IAM misconfigurations are reported to humans instead.
* Findings published by Endon components can trigger configuration remediation,
  but never principal or host containment, so a forged event on the Endon bus
  cannot be used to lock people out.
"""

from __future__ import annotations

from dataclasses import dataclass
from fnmatch import fnmatchcase

from endon_core.findings import Finding, Severity

AWS_DETECTORS = ("aws.guardduty", "aws.securityhub")


@dataclass(frozen=True)
class Playbook:
    name: str
    summary: str
    actions: tuple[str, ...]
    # CONTAIN actions run only at or above this severity; everything else still runs.
    min_severity: Severity = Severity.MEDIUM


@dataclass(frozen=True)
class Rule:
    playbook: Playbook
    types: tuple[str, ...]
    sources: tuple[str, ...] | None = None
    resource_role: str | None = None  # GuardDuty service.resourceRole: ACTOR or TARGET

    def matches(self, finding: Finding) -> bool:
        if self.sources is not None and finding.source not in self.sources:
            return False
        if self.resource_role and finding.tags.get("resourceRole") != self.resource_role:
            return False
        return any(fnmatchcase(finding.type, pattern) for pattern in self.types)


COMPROMISED_CREDENTIALS = Playbook(
    name="compromised-credentials",
    summary="Contain an IAM principal whose credentials are being used maliciously.",
    actions=("disable_access_keys", "quarantine_iam_user", "revoke_role_sessions", "notify"),
)

INSTANCE_CREDENTIAL_EXFILTRATION = Playbook(
    name="instance-credential-exfiltration",
    summary="EC2 role credentials used outside AWS: revoke the stolen sessions and "
    "collect evidence from the instance they were taken from.",
    actions=("revoke_role_sessions", "tag_for_review", "request_forensics", "notify"),
)

LOGGING_TAMPERING = Playbook(
    name="logging-tampering",
    summary="Restore audit logging, then contain the principal that disabled it.",
    actions=(
        "restore_cloudtrail_logging",
        "disable_access_keys",
        "quarantine_iam_user",
        "revoke_role_sessions",
        "notify",
    ),
)

COMPROMISED_EC2 = Playbook(
    name="compromised-ec2",
    summary="Isolate an EC2 instance showing signs of compromise while preserving evidence.",
    actions=("isolate_instance", "request_forensics", "notify"),
)

EXPOSED_EC2 = Playbook(
    name="exposed-ec2",
    summary="Instance is being probed or brute-forced from the internet. It is a target, "
    "not yet compromised: flag the exposure instead of taking it offline.",
    actions=("tag_for_review", "notify"),
    min_severity=Severity.HIGH,
)

S3_PUBLIC_EXPOSURE = Playbook(
    name="s3-public-exposure",
    summary="Re-enable S3 Block Public Access on a bucket that was exposed.",
    actions=("block_s3_public_access", "notify"),
    min_severity=Severity.LOW,
)

ROOT_ACTIVITY = Playbook(
    name="root-account-activity",
    summary="Root credentials in use. Root cannot be safely auto-contained: alert humans.",
    actions=("notify",),
)

IAM_RISK_REVIEW = Playbook(
    name="iam-risk-review",
    summary="IAM misconfiguration from the analyzer: route to review. Automatically "
    "removing permissions breaks production, so this is never automated.",
    actions=("notify",),
)

TRIAGE = Playbook(
    name="triage",
    summary="No automated response defined: record the finding and notify if significant.",
    actions=("notify",),
)

RULES: tuple[Rule, ...] = (
    Rule(
        LOGGING_TAMPERING,
        ("Stealth:IAMUser/CloudTrailLoggingDisabled", "DefenseEvasion:IAMUser/*"),
        sources=AWS_DETECTORS,
    ),
    Rule(ROOT_ACTIVITY, ("Policy:IAMUser/RootCredentialUsage",)),
    Rule(
        INSTANCE_CREDENTIAL_EXFILTRATION,
        ("UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.*",),
        sources=AWS_DETECTORS,
    ),
    Rule(
        S3_PUBLIC_EXPOSURE,
        (
            "Policy:S3/BucketBlockPublicAccessDisabled",
            "Policy:S3/BucketAnonymousAccessGranted",
            "Policy:S3/BucketPublicAccessGranted",
            "SecurityHub:S3.8",
            "Posture:S3/BucketPubliclyAccessible",
            "DataProtection:S3/SensitiveDataPubliclyAccessible",
        ),
    ),
    # Brute force where the instance is the ACTOR means it is attacking others.
    Rule(
        COMPROMISED_EC2,
        ("UnauthorizedAccess:EC2/SSHBruteForce", "UnauthorizedAccess:EC2/RDPBruteForce"),
        sources=AWS_DETECTORS,
        resource_role="ACTOR",
    ),
    Rule(
        EXPOSED_EC2,
        (
            "UnauthorizedAccess:EC2/SSHBruteForce",
            "UnauthorizedAccess:EC2/RDPBruteForce",
            "Recon:EC2/PortProbeUnprotectedPort",
            "Recon:EC2/PortProbeEMRUnprotectedPort",
        ),
    ),
    Rule(
        COMPROMISED_EC2,
        (
            "Backdoor:EC2/*",
            "CryptoCurrency:EC2/*",
            "Trojan:EC2/*",
            "Impact:EC2/*",
            "Recon:EC2/Portscan",
            "UnauthorizedAccess:EC2/*",
            "Backdoor:Runtime/*",
            "CryptoCurrency:Runtime/*",
            "Execution:Runtime/*",
            "PrivilegeEscalation:Runtime/*",
            "DefenseEvasion:Runtime/*",
        ),
        sources=AWS_DETECTORS,
    ),
    Rule(
        COMPROMISED_CREDENTIALS,
        (
            "UnauthorizedAccess:IAMUser/*",
            "CredentialAccess:IAMUser/*",
            "Exfiltration:IAMUser/*",
            "Impact:IAMUser/*",
            "Persistence:IAMUser/*",
            "PrivilegeEscalation:IAMUser/*",
            "Exfiltration:S3/*",
            "Impact:S3/*",
            "UnauthorizedAccess:S3/*",
        ),
        sources=AWS_DETECTORS,
    ),
    Rule(IAM_RISK_REVIEW, ("IAM:*",)),
)


def select_playbook(finding: Finding) -> Playbook:
    for rule in RULES:
        if rule.matches(finding):
            return rule.playbook
    return TRIAGE
