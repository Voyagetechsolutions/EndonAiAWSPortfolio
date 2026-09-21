"""Service Control Policy guardrails, as Python-built policy documents.

SCPs set the *maximum* available permissions for the accounts they are attached to: an
explicit ``Deny`` here cannot be overridden by any IAM policy in the member account, not
even by an account administrator. That is what makes them the right place for controls that
must hold regardless of what happens inside an account.

Each guardrail is a small deny statement with precise conditions. The high-impact ones
exempt the security administrator (and, for the platform's own resources, the deployment
pipeline) via ``aws:PrincipalArn`` — so break-glass and legitimate operations still work.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from endon_landingzone.config import (
    APPROVED_REGIONS,
    ENDON_RESOURCE_EXEMPTIONS,
    GLOBAL_SERVICE_ACTIONS,
    PROTECTED_SERVICE_EXEMPTIONS,
)


@dataclass(frozen=True)
class Scp:
    id: str
    name: str
    description: str
    document: dict[str, Any]
    targets: tuple[str, ...] = field(default_factory=tuple)  # OU names it attaches to


def _deny(
    sid: str, actions, resources="*", condition: dict | None = None, not_action=False
) -> dict:
    statement: dict[str, Any] = {"Sid": sid, "Effect": "Deny", "Resource": resources}
    statement["NotAction" if not_action else "Action"] = actions
    if condition:
        statement["Condition"] = condition
    return statement


def _not_by(principals: tuple[str, ...]) -> dict:
    """Condition that makes a statement apply to everyone EXCEPT the listed principals."""
    return {"ArnNotLike": {"aws:PrincipalArn": list(principals)}}


def _policy(*statements: dict) -> dict:
    return {"Version": "2012-10-17", "Statement": list(statements)}


def protect_security_logging() -> Scp:
    return Scp(
        id="protect-security-logging",
        name="EndonProtectSecurityLogging",
        description="Prevent anyone but the security admin from disabling CloudTrail or Config.",
        document=_policy(
            _deny(
                "DenyDisableCloudTrail",
                [
                    "cloudtrail:StopLogging",
                    "cloudtrail:DeleteTrail",
                    "cloudtrail:UpdateTrail",
                    "cloudtrail:PutEventSelectors",
                ],
                condition=_not_by(PROTECTED_SERVICE_EXEMPTIONS),
            ),
            _deny(
                "DenyDisableConfig",
                [
                    "config:StopConfigurationRecorder",
                    "config:DeleteConfigurationRecorder",
                    "config:DeleteDeliveryChannel",
                    "config:PutDeliveryChannel",
                ],
                condition=_not_by(PROTECTED_SERVICE_EXEMPTIONS),
            ),
        ),
        targets=("Root",),
    )


def protect_detection_services() -> Scp:
    return Scp(
        id="protect-detection-services",
        name="EndonProtectDetectionServices",
        description="Prevent disabling GuardDuty, Security Hub or Config detection.",
        document=_policy(
            _deny(
                "DenyDisableGuardDuty",
                [
                    "guardduty:DeleteDetector",
                    "guardduty:UpdateDetector",
                    "guardduty:DisassociateFromMasterAccount",
                    "guardduty:DisassociateFromAdministratorAccount",
                    "guardduty:StopMonitoringMembers",
                    "guardduty:DeleteMembers",
                ],
                condition=_not_by(PROTECTED_SERVICE_EXEMPTIONS),
            ),
            _deny(
                "DenyDisableSecurityHub",
                [
                    "securityhub:DisableSecurityHub",
                    "securityhub:DeleteMembers",
                    "securityhub:DisassociateFromAdministratorAccount",
                    "securityhub:DisassociateMembers",
                ],
                condition=_not_by(PROTECTED_SERVICE_EXEMPTIONS),
            ),
        ),
        targets=("Workloads",),
    )


def region_allowlist(regions: tuple[str, ...] = APPROVED_REGIONS) -> Scp:
    return Scp(
        id="region-allowlist",
        name="EndonRegionAllowlist",
        description=f"Deny all actions outside approved regions ({', '.join(regions)}), except global services.",
        document=_policy(
            _deny(
                "DenyUnapprovedRegions",
                list(GLOBAL_SERVICE_ACTIONS),
                not_action=True,
                condition={
                    "StringNotEquals": {"aws:RequestedRegion": list(regions)},
                    "ArnNotLike": {"aws:PrincipalArn": list(PROTECTED_SERVICE_EXEMPTIONS)},
                },
            )
        ),
        targets=("Root",),
    )


def prevent_public_s3() -> Scp:
    return Scp(
        id="prevent-public-s3",
        name="EndonPreventPublicS3",
        description="Keep account-level Block Public Access on, and deny public bucket ACLs.",
        document=_policy(
            _deny(
                "DenyDisablingAccountBlockPublicAccess",
                ["s3:PutAccountPublicAccessBlock", "s3:DeleteAccountPublicAccessBlock"],
                condition=_not_by(PROTECTED_SERVICE_EXEMPTIONS),
            ),
            _deny(
                "DenyPublicBucketAcls",
                ["s3:PutBucketAcl", "s3:PutObjectAcl", "s3:CreateBucket"],
                condition={
                    "StringEquals": {
                        "s3:x-amz-acl": ["public-read", "public-read-write", "authenticated-read"]
                    }
                },
            ),
        ),
        targets=("Workloads", "Sandbox"),
    )


def protect_endon_platform() -> Scp:
    return Scp(
        id="protect-endon-platform",
        name="EndonProtectPlatform",
        description="Only the deployment pipeline and security admin may change Endon AI resources.",
        document=_policy(
            _deny(
                "DenyModifyEndonRoles",
                [
                    "iam:DeleteRole",
                    "iam:PutRolePolicy",
                    "iam:DeleteRolePolicy",
                    "iam:AttachRolePolicy",
                    "iam:DetachRolePolicy",
                    "iam:UpdateAssumeRolePolicy",
                    "iam:DeleteRolePermissionsBoundary",
                ],
                resources=["arn:aws:iam::*:role/Endon*", "arn:aws:iam::*:role/endon-*"],
                condition=_not_by(ENDON_RESOURCE_EXEMPTIONS),
            ),
            _deny(
                "DenyModifyEndonFunctionsAndRules",
                [
                    "lambda:DeleteFunction",
                    "lambda:UpdateFunctionCode",
                    "lambda:UpdateFunctionConfiguration",
                    "lambda:AddPermission",
                    "events:DeleteRule",
                    "events:DisableRule",
                    "events:PutRule",
                    "events:RemoveTargets",
                ],
                resources=[
                    "arn:aws:lambda:*:*:function:Endon*",
                    "arn:aws:lambda:*:*:function:endon-*",
                    "arn:aws:events:*:*:rule/Endon*",
                    "arn:aws:events:*:*:rule/endon-*",
                ],
                condition=_not_by(ENDON_RESOURCE_EXEMPTIONS),
            ),
        ),
        targets=("Workloads", "Security"),
    )


def prevent_leaving_organization() -> Scp:
    return Scp(
        id="prevent-leaving-organization",
        name="EndonPreventLeavingOrganization",
        description="Deny removing an account from the organization.",
        document=_policy(_deny("DenyLeaveOrganization", ["organizations:LeaveOrganization"])),
        targets=("Root",),
    )


def deny_root_user() -> Scp:
    return Scp(
        id="deny-root-user",
        name="EndonDenyRootUser",
        description="Deny all actions performed by an account's root user.",
        document=_policy(
            _deny(
                "DenyAllRootUserActions",
                ["*"],
                condition={"StringLike": {"aws:PrincipalArn": ["arn:aws:iam::*:root"]}},
            )
        ),
        targets=("Root",),
    )


_BUILDERS = (
    protect_security_logging,
    protect_detection_services,
    region_allowlist,
    prevent_public_s3,
    protect_endon_platform,
    prevent_leaving_organization,
    deny_root_user,
)

SCP_CATALOG: tuple[Scp, ...] = tuple(builder() for builder in _BUILDERS)


def scp_by_id(scp_id: str) -> Scp:
    for scp in SCP_CATALOG:
        if scp.id == scp_id:
            return scp
    raise KeyError(scp_id)
