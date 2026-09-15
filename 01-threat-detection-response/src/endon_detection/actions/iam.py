"""Contain compromised IAM users and roles.

Nothing here deletes anything. Keys are deactivated rather than deleted and
access is removed with explicit-deny inline policies, so evidence survives and
every change can be reversed once the investigation is complete.
"""

from __future__ import annotations

import json

from endon_core.findings import Resource
from endon_core.incidents import ActionKind
from endon_core.timeutil import isoformat, utc_now
from endon_detection.actions.base import Action, ActionContext, ActionOutcome, ActionSkipped
from endon_detection.actions.resources import incident_tags, role_name, user_name

QUARANTINE_POLICY_NAME = "EndonQuarantineDenyAll"
REVOKE_SESSIONS_POLICY_NAME = "EndonRevokeOlderSessions"

# An explicit Deny overrides every Allow, including AdministratorAccess.
QUARANTINE_POLICY = {
    "Version": "2012-10-17",
    "Statement": [
        {"Sid": "EndonIncidentQuarantine", "Effect": "Deny", "Action": "*", "Resource": "*"}
    ],
}


def revoke_sessions_policy(issued_before: str) -> dict:
    """Deny every session issued before the cutoff; new, legitimate sessions still work.

    This is the same mechanism as "Revoke active sessions" in the IAM console. It is
    the only way to invalidate temporary credentials, which cannot be deleted.
    """
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "EndonRevokeOlderSessions",
                "Effect": "Deny",
                "Action": "*",
                "Resource": "*",
                "Condition": {"DateLessThan": {"aws:TokenIssueTime": issued_before}},
            }
        ],
    }


class DisableAccessKeys(Action):
    name = "disable_access_keys"
    kind = ActionKind.CONTAIN
    resource_types = ("AwsIamUser",)

    def plan(self, target: Resource, ctx: ActionContext) -> str:
        return f"deactivate every active access key for IAM user {user_name(target)}"

    def execute(self, target: Resource, ctx: ActionContext) -> ActionOutcome:
        iam = ctx.clients("iam")
        user = user_name(target)
        disabled: list[str] = []
        # All keys, not just the one in the finding: attackers create extra keys for persistence.
        for page in iam.get_paginator("list_access_keys").paginate(UserName=user):
            for key in page["AccessKeyMetadata"]:
                if key["Status"] == "Active":
                    iam.update_access_key(
                        UserName=user, AccessKeyId=key["AccessKeyId"], Status="Inactive"
                    )
                    disabled.append(key["AccessKeyId"])
        if not disabled:
            raise ActionSkipped(f"IAM user {user} has no active access keys")
        return ActionOutcome(
            f"Deactivated {len(disabled)} access key(s) for IAM user {user}",
            {"userName": user, "deactivatedAccessKeyIds": disabled},
        )


class QuarantineIamUser(Action):
    name = "quarantine_iam_user"
    kind = ActionKind.CONTAIN
    resource_types = ("AwsIamUser",)

    def plan(self, target: Resource, ctx: ActionContext) -> str:
        return f"attach inline deny-all policy {QUARANTINE_POLICY_NAME} to IAM user {user_name(target)}"

    def execute(self, target: Resource, ctx: ActionContext) -> ActionOutcome:
        iam = ctx.clients("iam")
        user = user_name(target)
        iam.put_user_policy(
            UserName=user,
            PolicyName=QUARANTINE_POLICY_NAME,
            PolicyDocument=json.dumps(QUARANTINE_POLICY),
        )
        iam.tag_user(UserName=user, Tags=incident_tags(ctx.incident.incident_id, "QUARANTINED"))
        return ActionOutcome(
            f"Quarantined IAM user {user} with explicit deny-all policy",
            {"userName": user, "policyName": QUARANTINE_POLICY_NAME},
        )


class RevokeRoleSessions(Action):
    name = "revoke_role_sessions"
    kind = ActionKind.CONTAIN
    resource_types = ("AwsIamRole",)

    def plan(self, target: Resource, ctx: ActionContext) -> str:
        return f"revoke all active sessions for IAM role {role_name(target)}"

    def execute(self, target: Resource, ctx: ActionContext) -> ActionOutcome:
        iam = ctx.clients("iam")
        role = role_name(target)
        cutoff = isoformat(utc_now(), timespec="seconds")
        iam.put_role_policy(
            RoleName=role,
            PolicyName=REVOKE_SESSIONS_POLICY_NAME,
            PolicyDocument=json.dumps(revoke_sessions_policy(cutoff)),
        )
        iam.tag_role(
            RoleName=role, Tags=incident_tags(ctx.incident.incident_id, "SESSIONS_REVOKED")
        )
        return ActionOutcome(
            f"Revoked sessions issued before {cutoff} for IAM role {role}",
            {"roleName": role, "policyName": REVOKE_SESSIONS_POLICY_NAME, "issuedBefore": cutoff},
        )
