"""Account-level IAM posture: password policy and root credentials.

This is a light, account-wide check. Deep IAM analysis (over-privilege and
privilege-escalation paths) is Project 2's job; here the scanner covers the basic
account hygiene a posture baseline is expected to include.
"""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any

from botocore.exceptions import ClientError

from endon_core.aws import error_code
from endon_core.findings import Finding
from endon_posture.checks.base import check
from endon_posture.context import ScanContext

MIN_PASSWORD_LENGTH = 14


@check("IAM")
def account_iam(ctx: ScanContext) -> Iterator[Finding]:
    # IAM is global; evaluate it once, in us-east-1, to avoid duplicate findings per region.
    if ctx.region != "us-east-1":
        return
    iam = ctx.clients("iam")
    resource = ctx.account_resource()

    if _password_policy_is_weak(iam):
        yield ctx.finding("IAM-001", resource)

    summary = iam.get_account_summary().get("SummaryMap", {})
    if summary.get("AccountAccessKeysPresent", 0) > 0:
        yield ctx.finding("IAM-002", resource)
    if summary.get("AccountMFAEnabled", 0) == 0:
        yield ctx.finding("IAM-003", resource)


def _password_policy_is_weak(iam: Any) -> bool:
    try:
        policy = iam.get_account_password_policy()["PasswordPolicy"]
    except ClientError as exc:
        if error_code(exc) == "NoSuchEntity":
            return True  # no policy at all
        raise
    return policy.get("MinimumPasswordLength", 0) < MIN_PASSWORD_LENGTH
