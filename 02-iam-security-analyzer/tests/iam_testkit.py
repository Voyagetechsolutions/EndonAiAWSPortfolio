"""A deliberately vulnerable IAM account, shared by the tests and the attack simulation.

Every issue the analyzer looks for is planted exactly once (with a couple of
deliberate non-issues to check for false positives), so a scan of this account has a
known, assertable set of findings.
"""

from __future__ import annotations

from datetime import UTC, datetime

from endon_iam_analyzer.models import AccountSnapshot

ACCOUNT_ID = "111122223333"
EXTERNAL_ACCOUNT = "999888777666"
# All credential ages are measured against this fixed "now".
NOW = datetime(2026, 9, 15, tzinfo=UTC)


def _arn(kind: str, name: str) -> str:
    return f"arn:aws:iam::{ACCOUNT_ID}:{kind}/{name}"


def _policy(*statements: dict) -> dict:
    return {"Version": "2012-10-17", "Statement": list(statements)}


def _allow(actions, resource="*", **extra) -> dict:
    return {"Effect": "Allow", "Action": actions, "Resource": resource, **extra}


POLICIES = {
    # AWS managed admin - attached in several places, never itself a "customer policy" finding.
    "arn:aws:iam::aws:policy/AdministratorAccess": {
        "name": "AdministratorAccess",
        "document": _policy(_allow("*")),
    },
    "arn:aws:iam::aws:policy/ReadOnlyAccess": {
        "name": "ReadOnlyAccess",
        "document": _policy(_allow(["s3:Get*", "s3:List*"])),
    },
    _arn("policy", "DeveloperWildcard"): {
        "name": "DeveloperWildcard",
        "document": _policy(_allow(["s3:*", "ec2:*"])),
    },
    _arn("policy", "EscalateViaPassRole"): {
        "name": "EscalateViaPassRole",
        "document": _policy(
            _allow(["iam:PassRole", "lambda:CreateFunction", "lambda:InvokeFunction"])
        ),
    },
    _arn("policy", "AttachAnyPolicy"): {
        "name": "AttachAnyPolicy",
        "document": _policy(_allow("iam:AttachUserPolicy")),
    },
    _arn("policy", "NotActionAdmin"): {
        "name": "NotActionAdmin",
        "document": _policy({"Effect": "Allow", "NotAction": "s3:GetObject", "Resource": "*"}),
    },
    # A correctly scoped policy: no wildcard, no escalation. Must produce no finding.
    _arn("policy", "ScopedS3Reader"): {
        "name": "ScopedS3Reader",
        "document": _policy(_allow(["s3:GetObject"], resource="arn:aws:s3:::reports/*")),
    },
    _arn("policy", "AssumeEscalationTarget"): {
        "name": "AssumeEscalationTarget",
        "document": _policy(
            _allow("sts:AssumeRole", resource=_arn("role", "escalation-target-role"))
        ),
    },
}


def _trust(*principals: str, condition: dict | None = None) -> dict:
    statement = {
        "Effect": "Allow",
        "Principal": {"AWS": list(principals)},
        "Action": "sts:AssumeRole",
    }
    if condition:
        statement["Condition"] = condition
    return {"Version": "2012-10-17", "Statement": [statement]}


def vulnerable_account() -> dict:
    return {
        "account_id": ACCOUNT_ID,
        "region": "us-east-1",
        "policies": POLICIES,
        "users": [
            {
                "name": "alice-admin",
                "attached": ["arn:aws:iam::aws:policy/AdministratorAccess"],
                "credentials": {
                    "password_enabled": True,
                    "mfa_active": False,
                    "access_key_1_active": True,
                    "access_key_1_last_rotated": "2026-01-01T00:00:00Z",
                    "access_key_1_last_used": "2026-09-14T00:00:00Z",
                    "access_key_2_active": True,
                    "access_key_2_last_rotated": "2026-09-10T00:00:00Z",
                    "access_key_2_last_used": "N/A",
                },
            },
            {
                "name": "bob-escalator",
                "attached": [_arn("policy", "AttachAnyPolicy")],
            },
            {
                "name": "carol-passrole",
                "attached": [_arn("policy", "EscalateViaPassRole")],
            },
            {
                "name": "dave-wildcard",
                "inline": {"InlineIamAdmin": _policy(_allow("iam:*"))},
                "attached": [_arn("policy", "NotActionAdmin")],
            },
            {
                "name": "erin-readonly",
                "attached": [
                    "arn:aws:iam::aws:policy/ReadOnlyAccess",
                    _arn("policy", "ScopedS3Reader"),
                ],
                "credentials": {
                    "password_enabled": True,
                    "mfa_active": True,
                    "access_key_1_active": True,
                    "access_key_1_last_rotated": "2026-09-01T00:00:00Z",
                    "access_key_1_last_used": "2026-09-14T00:00:00Z",
                },
            },
            {
                "name": "break-glass",
                "attached": ["arn:aws:iam::aws:policy/AdministratorAccess"],
                "tags": {"endon:protected": "true"},
            },
            {
                "name": "mallory",
                "attached": [_arn("policy", "AssumeEscalationTarget")],
            },
            {
                "name": "<root_account>",
                "arn": f"arn:aws:iam::{ACCOUNT_ID}:root",
                "credentials": {
                    "password_enabled": False,
                    "mfa_active": False,
                    "access_key_1_active": True,
                    "access_key_1_last_rotated": "2021-01-01T00:00:00Z",
                    "access_key_1_last_used": "2026-09-01T00:00:00Z",
                },
            },
        ],
        "roles": [
            {
                "name": "deployer-role",
                "attached": ["arn:aws:iam::aws:policy/AdministratorAccess"],
                "trust": _trust(f"arn:aws:iam::{EXTERNAL_ACCOUNT}:root"),
            },
            {
                "name": "public-role",
                "attached": [_arn("policy", "ScopedS3Reader")],
                "trust": {
                    "Version": "2012-10-17",
                    "Statement": [
                        {"Effect": "Allow", "Principal": "*", "Action": "sts:AssumeRole"}
                    ],
                },
            },
            {
                "name": "escalation-target-role",
                "attached": [_arn("policy", "AttachAnyPolicy")],
                "trust": _trust(_arn("user", "mallory")),
            },
            {
                "name": "partner-role",
                "attached": [_arn("policy", "ScopedS3Reader")],
                # External trust WITH an ExternalId condition: correctly configured, no finding.
                "trust": _trust(
                    f"arn:aws:iam::{EXTERNAL_ACCOUNT}:root",
                    condition={"StringEquals": {"sts:ExternalId": "endon-shared-secret"}},
                ),
            },
            {
                "name": "AWSServiceRoleForAutoScaling",
                "path": "/aws-service-role/autoscaling.amazonaws.com/",
                "attached": ["arn:aws:iam::aws:policy/AdministratorAccess"],
                "trust": _trust("autoscaling.amazonaws.com"),
            },
        ],
        "groups": [],
    }


def vulnerable_snapshot() -> AccountSnapshot:
    return AccountSnapshot.from_dict(vulnerable_account())
