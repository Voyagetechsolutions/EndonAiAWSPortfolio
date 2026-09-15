"""S3 posture checks: public exposure, encryption, TLS, versioning, logging."""

from __future__ import annotations

import json
from collections.abc import Iterator
from typing import Any

from botocore.exceptions import ClientError

from endon_core.aws import error_code
from endon_core.findings import Finding, Resource
from endon_posture.checks.base import check
from endon_posture.context import ScanContext

_ALL_USERS = "http://acs.amazonaws.com/groups/global/AllUsers"
_AUTH_USERS = "http://acs.amazonaws.com/groups/global/AuthenticatedUsers"
_FULL_BLOCK = {"BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets"}


@check("S3")
def s3_buckets(ctx: ScanContext) -> Iterator[Finding]:
    s3 = ctx.clients("s3")
    for name in _list_buckets(s3):
        if _bucket_region(s3, name) != ctx.region:
            continue  # scan each bucket in its home region only
        yield from _scan_bucket(ctx, s3, name)


def _scan_bucket(ctx: ScanContext, s3: Any, name: str) -> Iterator[Finding]:
    resource = Resource(
        "AwsS3Bucket", f"arn:{ctx.partition}:s3:::{name}", details={"bucketName": name}
    )
    block = _public_access_block(s3, name)
    fully_blocked = _FULL_BLOCK.issubset({k for k, v in block.items() if v})

    public_acl = _has_public_acl(s3, name)
    policy = _bucket_policy(s3, name)
    public_policy = _policy_is_public(policy)
    if (public_acl or public_policy) and not fully_blocked:
        source = " and ".join(
            filter(
                None,
                [
                    "a public ACL" if public_acl else "",
                    "a wildcard-principal policy" if public_policy else "",
                ],
            )
        )
        yield ctx.finding("S3-001", resource, detail=f"Exposed via {source}.")

    if not fully_blocked:
        missing = sorted(_FULL_BLOCK - {k for k, v in block.items() if v})
        yield ctx.finding("S3-002", resource, detail=f"Missing settings: {', '.join(missing)}.")

    if not _has_default_encryption(s3, name):
        yield ctx.finding("S3-003", resource)

    if not _enforces_tls(policy):
        yield ctx.finding("S3-004", resource)

    if _versioning_status(s3, name) != "Enabled":
        yield ctx.finding("S3-005", resource)

    if not _logging_enabled(s3, name):
        yield ctx.finding("S3-006", resource)


def _list_buckets(s3: Any) -> list[str]:
    return [b["Name"] for b in s3.list_buckets().get("Buckets", [])]


def _bucket_region(s3: Any, name: str) -> str:
    try:
        location = s3.get_bucket_location(Bucket=name).get("LocationConstraint")
    except ClientError:
        return ""
    # us-east-1 is returned as None; EU legacy alias maps to eu-west-1.
    return {None: "us-east-1", "EU": "eu-west-1"}.get(location, location)


def _public_access_block(s3: Any, name: str) -> dict[str, bool]:
    try:
        return s3.get_public_access_block(Bucket=name)["PublicAccessBlockConfiguration"]
    except ClientError as exc:
        if error_code(exc) in ("NoSuchPublicAccessBlockConfiguration", "NoSuchBucket"):
            return {}
        raise


def _has_public_acl(s3: Any, name: str) -> bool:
    try:
        grants = s3.get_bucket_acl(Bucket=name).get("Grants", [])
    except ClientError:
        return False
    return any((g.get("Grantee") or {}).get("URI") in (_ALL_USERS, _AUTH_USERS) for g in grants)


def _bucket_policy(s3: Any, name: str) -> dict[str, Any] | None:
    try:
        return json.loads(s3.get_bucket_policy(Bucket=name)["Policy"])
    except ClientError as exc:
        if error_code(exc) in ("NoSuchBucketPolicy", "NoSuchBucket"):
            return None
        raise


def _policy_is_public(policy: dict[str, Any] | None) -> bool:
    if not policy:
        return False
    for statement in _statements(policy):
        if statement.get("Effect") != "Allow":
            continue
        principal = statement.get("Principal")
        is_wildcard = principal == "*" or (
            isinstance(principal, dict) and "*" in _flatten(principal.get("AWS"))
        )
        # A wildcard principal is only public if not narrowed by a condition (e.g. aws:SourceVpce).
        if is_wildcard and not statement.get("Condition"):
            return True
    return False


def _enforces_tls(policy: dict[str, Any] | None) -> bool:
    if not policy:
        return False
    for statement in _statements(policy):
        if statement.get("Effect") != "Deny":
            continue
        condition = statement.get("Condition") or {}
        secure = (condition.get("Bool") or {}).get("aws:SecureTransport")
        if str(secure).lower() == "false":
            return True
    return False


def _has_default_encryption(s3: Any, name: str) -> bool:
    try:
        s3.get_bucket_encryption(Bucket=name)
        return True
    except ClientError as exc:
        if error_code(exc) in ("ServerSideEncryptionConfigurationNotFoundError", "NoSuchBucket"):
            return False
        raise


def _versioning_status(s3: Any, name: str) -> str:
    try:
        return s3.get_bucket_versioning(Bucket=name).get("Status", "Disabled")
    except ClientError:
        return "Disabled"


def _logging_enabled(s3: Any, name: str) -> bool:
    try:
        return "LoggingEnabled" in s3.get_bucket_logging(Bucket=name)
    except ClientError:
        return False


def _statements(policy: dict[str, Any]) -> list[dict[str, Any]]:
    raw = policy.get("Statement", [])
    return raw if isinstance(raw, list) else [raw]


def _flatten(value: Any) -> list[Any]:
    if value is None:
        return []
    return value if isinstance(value, list) else [value]
