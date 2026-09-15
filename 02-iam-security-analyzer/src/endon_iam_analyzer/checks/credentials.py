"""Credential-hygiene checks driven by the IAM credential report."""

from __future__ import annotations

from collections.abc import Iterator

from endon_core.findings import Finding, Resource, Severity
from endon_iam_analyzer.checks.base import CheckContext, check
from endon_iam_analyzer.models import CredentialInfo, Principal
from endon_iam_analyzer.timeutil import age_in_days

STALE_KEY_DAYS = 90
UNUSED_DAYS = 90


@check
def credential_hygiene(ctx: CheckContext) -> Iterator[Finding]:
    for principal in ctx.snapshot.users.values():
        # The root user is covered by the dedicated root_account check.
        if principal.credentials is None or principal.credentials.is_root:
            continue
        yield from _user_findings(ctx, principal, principal.credentials)


@check
def root_account(ctx: CheckContext) -> Iterator[Finding]:
    root = next(
        (
            u.credentials
            for u in ctx.snapshot.users.values()
            if u.credentials and u.credentials.is_root
        ),
        None,
    )
    if root is None:
        return
    resource = ctx.account_resource()
    if root.active_key_count:
        yield ctx.finding(
            finding_type="IAM:Root/AccessKeyActive",
            title="The account root user has active access keys",
            severity=Severity.CRITICAL,
            resources=[resource],
            description=(
                "The root user has one or more active access keys. Root cannot be scoped or "
                "constrained by IAM policy, so a leaked root key is unlimited and unrecoverable."
            ),
            remediation="Delete all root access keys. Operate through IAM roles and users instead.",
            control_id="IAM-ROOT-001",
        )
    if not root.mfa_active:
        yield ctx.finding(
            finding_type="IAM:Root/MfaDisabled",
            title="The account root user does not have MFA enabled",
            severity=Severity.HIGH,
            resources=[resource],
            description="MFA is not enabled on the root user, the most privileged identity in the account.",
            remediation="Enable a hardware or virtual MFA device on the root user.",
            control_id="IAM-ROOT-002",
        )


def _user_findings(
    ctx: CheckContext, principal: Principal, creds: CredentialInfo
) -> Iterator[Finding]:
    resource = principal.to_resource()

    if creds.password_enabled and not creds.mfa_active:
        yield ctx.finding(
            finding_type="IAM:User/MissingMfa",
            title=f"User {principal.name} has console access without MFA",
            severity=Severity.HIGH,
            resources=[resource],
            description=f"User '{principal.name}' can sign in to the console but has no MFA device.",
            remediation="Enforce MFA with an IAM policy condition (aws:MultiFactorAuthPresent).",
            control_id="IAM-CRED-001",
        )

    active_keys = creds.active_keys()
    if len(active_keys) > 1:
        yield ctx.finding(
            finding_type="IAM:User/MultipleActiveKeys",
            title=f"User {principal.name} has {len(active_keys)} active access keys",
            severity=Severity.MEDIUM,
            resources=[resource],
            description=f"User '{principal.name}' has more than one active access key, doubling the exposure.",
            remediation="Keep a single active key and delete the extra one after rotating dependents.",
            control_id="IAM-CRED-002",
        )

    for slot, last_rotated, last_used in active_keys:
        rotated_age = age_in_days(last_rotated, ctx.now)
        if rotated_age is not None and rotated_age > STALE_KEY_DAYS:
            yield ctx.finding(
                finding_type="IAM:AccessKey/Stale",
                title=f"User {principal.name} access key {slot} is {rotated_age} days old",
                severity=Severity.HIGH,
                resources=[_key_resource(principal, slot)],
                description=f"Access key {slot} for '{principal.name}' has not been rotated in {rotated_age} days.",
                remediation=f"Rotate access key {slot} and delete the old one once dependents are updated.",
                control_id="IAM-CRED-003",
                tags={"keySlot": slot, "ageDays": str(rotated_age)},
            )
        used_age = age_in_days(last_used, ctx.now)
        if used_age is None or used_age > UNUSED_DAYS:
            never = last_used in (None, "N/A", "no_information")
            detail = "has never been used" if never else f"was last used {used_age} days ago"
            yield ctx.finding(
                finding_type="IAM:AccessKey/Unused",
                title=f"User {principal.name} access key {slot} appears unused",
                severity=Severity.MEDIUM,
                resources=[_key_resource(principal, slot)],
                description=f"Access key {slot} for '{principal.name}' {detail}. Unused keys are pure risk.",
                remediation=f"Delete access key {slot} if it is no longer needed.",
                control_id="IAM-CRED-004",
                tags={"keySlot": slot},
            )


def _key_resource(principal: Principal, slot: str) -> Resource:
    return Resource(
        "AwsIamAccessKey", f"{principal.arn}/accesskey/{slot}", details={"user": principal.name}
    )
