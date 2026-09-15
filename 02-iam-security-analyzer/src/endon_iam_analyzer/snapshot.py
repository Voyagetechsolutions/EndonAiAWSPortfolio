"""Build an ``AccountSnapshot`` from a live account with boto3.

`iam:GetAccountAuthorizationDetails` returns every user, group, role and attached
policy document in a handful of paginated calls, so the whole account is captured
without a call per principal. The credential report adds password, MFA and access-key
state. Policy documents come back URL-encoded, so they are decoded here.
"""

from __future__ import annotations

import csv
import io
import json
import time
from typing import Any
from urllib.parse import unquote

from endon_core.aws import ClientFactory
from endon_iam_analyzer.models import (
    AccountSnapshot,
    CredentialInfo,
    ManagedPolicy,
    Principal,
)
from endon_iam_analyzer.policy import PolicyDocument


def _decode_document(document: Any) -> dict:
    if isinstance(document, dict):
        return document
    if isinstance(document, str):
        return json.loads(unquote(document))
    return {}


def build_snapshot(clients: ClientFactory, region: str = "us-east-1") -> AccountSnapshot:
    iam = clients("iam")
    account_id = clients("sts").get_caller_identity()["Account"]
    partition = _partition(region)
    snapshot = AccountSnapshot(account_id=account_id, region=region, partition=partition)

    details = _account_authorization_details(iam)
    for raw in details["Policies"]:
        default = next(
            (v for v in raw.get("PolicyVersionList", []) if v.get("IsDefaultVersion")),
            None,
        )
        document = (
            PolicyDocument.parse(_decode_document(default["Document"]))
            if default
            else PolicyDocument(())
        )
        arn = raw["Arn"]
        snapshot.policies[arn] = ManagedPolicy(
            arn=arn,
            # Real AWS includes PolicyName; some emulators omit it, so fall back to the ARN.
            name=raw.get("PolicyName") or arn.rsplit("/", 1)[-1],
            document=document,
            attachment_count=raw.get("AttachmentCount", 0),
        )

    for raw in details["UserDetailList"]:
        snapshot.users[raw["UserName"]] = _user(raw)
    for raw in details["GroupDetailList"]:
        snapshot.groups[raw["GroupName"]] = _group(raw)
    for raw in details["RoleDetailList"]:
        snapshot.roles[raw["RoleName"]] = _role(raw)

    _attach_credential_report(iam, snapshot)
    return snapshot


def _account_authorization_details(iam: Any) -> dict[str, list]:
    combined: dict[str, list] = {
        "UserDetailList": [],
        "GroupDetailList": [],
        "RoleDetailList": [],
        "Policies": [],
    }
    paginator = iam.get_paginator("get_account_authorization_details")
    for page in paginator.paginate(
        Filter=["User", "Group", "Role", "LocalManagedPolicy", "AWSManagedPolicy"]
    ):
        for key in combined:
            combined[key].extend(page.get(key, []))
    return combined


def _user(raw: dict) -> Principal:
    return Principal(
        kind="user",
        name=raw["UserName"],
        arn=raw["Arn"],
        path=raw.get("Path", "/"),
        inline_policies=_inline(raw.get("UserPolicyList", [])),
        attached_policy_arns=[p["PolicyArn"] for p in raw.get("AttachedManagedPolicies", [])],
        group_names=list(raw.get("GroupList", [])),
        tags=_tags(raw.get("Tags", [])),
    )


def _group(raw: dict) -> Principal:
    return Principal(
        kind="group",
        name=raw["GroupName"],
        arn=raw["Arn"],
        path=raw.get("Path", "/"),
        inline_policies=_inline(raw.get("GroupPolicyList", [])),
        attached_policy_arns=[p["PolicyArn"] for p in raw.get("AttachedManagedPolicies", [])],
    )


def _role(raw: dict) -> Principal:
    trust = raw.get("AssumeRolePolicyDocument")
    return Principal(
        kind="role",
        name=raw["RoleName"],
        arn=raw["Arn"],
        path=raw.get("Path", "/"),
        inline_policies=_inline(raw.get("RolePolicyList", [])),
        attached_policy_arns=[p["PolicyArn"] for p in raw.get("AttachedManagedPolicies", [])],
        trust_policy=PolicyDocument.parse(_decode_document(trust)) if trust else None,
        tags=_tags(raw.get("Tags", [])),
    )


def _inline(policy_list: list[dict]) -> dict[str, PolicyDocument]:
    return {
        p["PolicyName"]: PolicyDocument.parse(_decode_document(p["PolicyDocument"]))
        for p in policy_list
    }


def _tags(tags: list[dict]) -> dict[str, str]:
    return {t["Key"]: t["Value"] for t in tags}


def _attach_credential_report(iam: Any, snapshot: AccountSnapshot) -> None:
    report = _credential_report(iam)
    if report is None:
        return
    rows = csv.DictReader(io.StringIO(report))
    for row in rows:
        info = _credential_info(row)
        if info.is_root:
            # Represent the root user so the root checks can find it.
            snapshot.users.setdefault(
                "<root_account>",
                Principal(kind="user", name="<root_account>", arn=info.arn, path="/"),
            ).credentials = info
        elif info.user in snapshot.users:
            snapshot.users[info.user].credentials = info


def _credential_report(iam: Any) -> str | None:
    for _ in range(10):
        try:
            return iam.get_credential_report()["Content"].decode("utf-8")
        except iam.exceptions.CredentialReportNotPresentException:
            iam.generate_credential_report()
        except iam.exceptions.CredentialReportNotReadyException:
            time.sleep(1)
    return None


def _credential_info(row: dict) -> CredentialInfo:
    def flag(key: str) -> bool:
        return row.get(key, "false").strip().lower() == "true"

    def value(key: str) -> str | None:
        raw = row.get(key)
        return raw if raw and raw.upper() != "N/A" else None

    return CredentialInfo(
        user=row["user"],
        arn=row.get("arn", ""),
        password_enabled=flag("password_enabled"),
        mfa_active=flag("mfa_active"),
        access_key_1_active=flag("access_key_1_active"),
        access_key_1_last_rotated=value("access_key_1_last_rotated"),
        access_key_1_last_used=value("access_key_1_last_used_date"),
        access_key_2_active=flag("access_key_2_active"),
        access_key_2_last_rotated=value("access_key_2_last_rotated"),
        access_key_2_last_used=value("access_key_2_last_used_date"),
    )


def _partition(region: str) -> str:
    if region.startswith("cn-"):
        return "aws-cn"
    if region.startswith("us-gov-"):
        return "aws-us-gov"
    return "aws"
