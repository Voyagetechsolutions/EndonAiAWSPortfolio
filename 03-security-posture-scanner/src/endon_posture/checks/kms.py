"""KMS posture: key rotation and wildcard key policies on customer-managed keys."""

from __future__ import annotations

import json
from collections.abc import Iterator
from typing import Any

from botocore.exceptions import ClientError

from endon_core.findings import Finding, Resource
from endon_posture.checks.base import check
from endon_posture.context import ScanContext


@check("KMS")
def kms_keys(ctx: ScanContext) -> Iterator[Finding]:
    kms = ctx.clients("kms")
    for page in kms.get_paginator("list_keys").paginate():
        for entry in page.get("Keys", []):
            key_id = entry["KeyId"]
            metadata = _describe(kms, key_id)
            if metadata is None or metadata.get("KeyManager") != "CUSTOMER":
                continue
            if metadata.get("KeyState") != "Enabled":
                continue
            resource = Resource(
                "AwsKmsKey",
                metadata.get("Arn", key_id),
                region=ctx.region,
                details={"keyId": key_id},
            )

            if not _rotation_enabled(kms, key_id):
                yield ctx.finding("KMS-001", resource)
            if _policy_has_wildcard_principal(kms, key_id):
                yield ctx.finding("KMS-002", resource)


def _describe(kms: Any, key_id: str) -> dict[str, Any] | None:
    try:
        return kms.describe_key(KeyId=key_id)["KeyMetadata"]
    except ClientError:
        return None


def _rotation_enabled(kms: Any, key_id: str) -> bool:
    try:
        return bool(kms.get_key_rotation_status(KeyId=key_id).get("KeyRotationEnabled"))
    except ClientError:
        return True  # e.g. keys where rotation is not applicable; avoid a false finding


def _policy_has_wildcard_principal(kms: Any, key_id: str) -> bool:
    try:
        policy = json.loads(kms.get_key_policy(KeyId=key_id, PolicyName="default")["Policy"])
    except ClientError:
        return False
    statements = policy.get("Statement", [])
    statements = statements if isinstance(statements, list) else [statements]
    for statement in statements:
        if statement.get("Effect") != "Allow":
            continue
        principal = statement.get("Principal")
        aws = principal.get("AWS") if isinstance(principal, dict) else principal
        values = aws if isinstance(aws, list) else [aws]
        if "*" in values and not statement.get("Condition"):
            return True
    return False
