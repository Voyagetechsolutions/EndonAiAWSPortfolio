"""Close public exposure of S3 buckets."""

from __future__ import annotations

from typing import Any

from botocore.exceptions import ClientError

from endon_core.aws import error_code
from endon_core.findings import Resource
from endon_core.incidents import ActionKind
from endon_detection.actions.base import Action, ActionContext, ActionOutcome
from endon_detection.actions.resources import bucket_name, incident_tags

_BLOCK_ALL = {
    "BlockPublicAcls": True,
    "IgnorePublicAcls": True,
    "BlockPublicPolicy": True,
    "RestrictPublicBuckets": True,
}
_MAX_BUCKET_TAGS = 50


class BlockS3PublicAccess(Action):
    name = "block_s3_public_access"
    kind = ActionKind.REMEDIATE
    resource_types = ("AwsS3Bucket",)

    def plan(self, target: Resource, ctx: ActionContext) -> str:
        return f"enable all four S3 Block Public Access settings on bucket {bucket_name(target)}"

    def execute(self, target: Resource, ctx: ActionContext) -> ActionOutcome:
        s3 = ctx.clients("s3")
        bucket = bucket_name(target)
        # IgnorePublicAcls and RestrictPublicBuckets neutralize existing public ACLs and
        # policies immediately, without editing them, so the exposure is preserved as evidence.
        s3.put_public_access_block(Bucket=bucket, PublicAccessBlockConfiguration=_BLOCK_ALL)
        tagged = _merge_bucket_tags(
            s3, bucket, incident_tags(ctx.incident.incident_id, "PUBLIC_ACCESS_BLOCKED")
        )
        return ActionOutcome(
            f"Enabled S3 Block Public Access on bucket {bucket}",
            {"bucketName": bucket, "publicAccessBlock": _BLOCK_ALL, "tagged": tagged},
        )


def _merge_bucket_tags(s3: Any, bucket: str, new_tags: list[dict[str, str]]) -> bool:
    """PutBucketTagging replaces the whole tag set, so merge with existing tags first."""
    try:
        existing = s3.get_bucket_tagging(Bucket=bucket)["TagSet"]
    except ClientError as exc:
        if error_code(exc) != "NoSuchTagSet":
            raise
        existing = []
    merged = {t["Key"]: t["Value"] for t in existing}
    merged.update({t["Key"]: t["Value"] for t in new_tags})
    if len(merged) > _MAX_BUCKET_TAGS:
        return False
    s3.put_bucket_tagging(
        Bucket=bucket, Tagging={"TagSet": [{"Key": k, "Value": v} for k, v in merged.items()]}
    )
    return True
