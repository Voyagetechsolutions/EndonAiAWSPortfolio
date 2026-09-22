"""How each control is detected: a predicate over a planned resource's attributes.

A rule pairs a control ID with the resource types it applies to and a predicate that returns
True when the resource *violates* the control. Keeping detection here (and meaning in
``controls.py``) means a new check is one small, testable function.

The IAM rules reuse Project 2's policy engine — the same deny-wins, wildcard-aware evaluator
that powers the live IAM analyzer — so "what counts as admin" is decided in exactly one place
whether the policy is live in an account or still a string in a Terraform plan.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass

from endon_iam_analyzer.policy import PermissionSet, PolicyDocument
from endon_tfscan.plan import Resource

_PUBLIC_ACLS = {"public-read", "public-read-write", "authenticated-read"}
_ADMIN_PORTS = (22, 3389)
_OPEN_CIDRS = {"0.0.0.0/0", "::/0"}


@dataclass(frozen=True)
class Rule:
    control_id: str
    resource_types: tuple[str, ...]
    predicate: Callable[[Resource], bool]


# ---- S3 ---------------------------------------------------------------------------
def _s3_public_acl(r: Resource) -> bool:
    return r.get("acl") in _PUBLIC_ACLS


def _s3_bpa_weak(r: Resource) -> bool:
    flags = (
        "block_public_acls",
        "block_public_policy",
        "ignore_public_acls",
        "restrict_public_buckets",
    )
    return any(r.get(flag) is False for flag in flags)


def _s3_no_encryption(r: Resource) -> bool:
    return not r.blocks("server_side_encryption_configuration")


def _s3_no_versioning(r: Resource) -> bool:
    versioning = r.blocks("versioning")
    return not versioning or not versioning[0].get("enabled", False)


# ---- Security groups --------------------------------------------------------------
def _ingress_is_open(rule: dict) -> bool:
    cidrs = set(rule.get("cidr_blocks") or []) | set(rule.get("ipv6_cidr_blocks") or [])
    return bool(cidrs & _OPEN_CIDRS)


def _covers_admin_port(rule: dict) -> bool:
    lo, hi = rule.get("from_port", 0), rule.get("to_port", 0)
    return any(lo <= port <= hi for port in _ADMIN_PORTS)


def _sg_admin_open(r: Resource) -> bool:
    return any(_ingress_is_open(i) and _covers_admin_port(i) for i in r.blocks("ingress"))


def _sg_open_non_admin(r: Resource) -> bool:
    return any(_ingress_is_open(i) and not _covers_admin_port(i) for i in r.blocks("ingress"))


# ---- Compute / storage ------------------------------------------------------------
def _imds_v1(r: Resource) -> bool:
    options = r.blocks("metadata_options")
    return not options or options[0].get("http_tokens") != "required"


def _ebs_unencrypted(r: Resource) -> bool:
    return r.get("encrypted") is not True


def _rds_unencrypted(r: Resource) -> bool:
    return r.get("storage_encrypted") is not True


def _rds_public(r: Resource) -> bool:
    return r.get("publicly_accessible") is True


# ---- IAM (reuses Project 2) -------------------------------------------------------
def _permission_set(r: Resource) -> PermissionSet | None:
    raw = r.get("policy")
    if not isinstance(raw, str):
        return None
    try:
        document = json.loads(raw)
    except (ValueError, TypeError):
        return None
    return PermissionSet(PolicyDocument.parse(document).statements)


def _iam_admin(r: Resource) -> bool:
    permissions = _permission_set(r)
    return bool(permissions and permissions.grants_admin())


def _iam_unscoped_passrole(r: Resource) -> bool:
    permissions = _permission_set(r)
    return bool(
        permissions and permissions.evaluate("iam:PassRole", "*").unconditional_on_any_resource
    )


# ---- KMS / CloudTrail -------------------------------------------------------------
def _kms_no_rotation(r: Resource) -> bool:
    return r.get("enable_key_rotation") is not True


def _cloudtrail_weak(r: Resource) -> bool:
    return r.get("is_multi_region_trail") is not True or not r.get("kms_key_id")


_IAM_POLICY_TYPES = (
    "aws_iam_policy",
    "aws_iam_role_policy",
    "aws_iam_user_policy",
    "aws_iam_group_policy",
)

RULES: tuple[Rule, ...] = (
    Rule("TF-S3-001", ("aws_s3_bucket",), _s3_public_acl),
    Rule("TF-S3-001", ("aws_s3_bucket_public_access_block",), _s3_bpa_weak),
    Rule("TF-S3-002", ("aws_s3_bucket",), _s3_no_encryption),
    Rule("TF-S3-003", ("aws_s3_bucket",), _s3_no_versioning),
    Rule("TF-EC2-001", ("aws_security_group",), _sg_admin_open),
    Rule("TF-EC2-002", ("aws_security_group",), _sg_open_non_admin),
    Rule("TF-EC2-003", ("aws_instance",), _imds_v1),
    Rule("TF-EBS-001", ("aws_ebs_volume",), _ebs_unencrypted),
    Rule("TF-RDS-001", ("aws_db_instance",), _rds_unencrypted),
    Rule("TF-RDS-002", ("aws_db_instance",), _rds_public),
    Rule("TF-IAM-001", _IAM_POLICY_TYPES, _iam_admin),
    Rule("TF-IAM-002", _IAM_POLICY_TYPES, _iam_unscoped_passrole),
    Rule("TF-KMS-001", ("aws_kms_key",), _kms_no_rotation),
    Rule("TF-LOG-001", ("aws_cloudtrail",), _cloudtrail_weak),
)
