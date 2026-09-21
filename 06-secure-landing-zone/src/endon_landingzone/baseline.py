"""The organization security baseline: the services that must be on, and where.

This is the intent the landing zone establishes. The organization CloudTrail is deployed
concretely by the CDK stack; the detective services are enabled with a delegated
administrator in the Security Tooling account (a management-account operation, documented
here and scripted in the deploy helper).
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class BaselineControl:
    id: str
    service: str
    description: str
    delegated_admin: bool  # administered from the Security Tooling account, not management
    scs_c03_domain: str


BASELINE = (
    BaselineControl(
        "org-cloudtrail",
        "CloudTrail",
        "A multi-region organization trail delivering to the Log Archive account's Object Lock bucket.",
        delegated_admin=False,
        scs_c03_domain="Governance",
    ),
    BaselineControl(
        "org-config",
        "AWS Config",
        "Config recorders in every account and region, aggregated to the Security Tooling account.",
        delegated_admin=True,
        scs_c03_domain="Governance",
    ),
    BaselineControl(
        "org-guardduty",
        "GuardDuty",
        "GuardDuty enabled org-wide with auto-enrollment of new accounts; findings aggregated to Endon.",
        delegated_admin=True,
        scs_c03_domain="Detection",
    ),
    BaselineControl(
        "org-securityhub",
        "Security Hub",
        "Security Hub enabled org-wide with the AWS Foundational Security Best Practices standard.",
        delegated_admin=True,
        scs_c03_domain="Detection",
    ),
    BaselineControl(
        "org-macie",
        "Macie",
        "Amazon Macie enabled org-wide for sensitive-data discovery (feeds Project 5).",
        delegated_admin=True,
        scs_c03_domain="Data Protection",
    ),
    BaselineControl(
        "account-block-public-access",
        "S3",
        "Account-level S3 Block Public Access enabled everywhere, locked on by SCP.",
        delegated_admin=False,
        scs_c03_domain="Data Protection",
    ),
)
