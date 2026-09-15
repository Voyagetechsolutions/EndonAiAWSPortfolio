import json

from endon_posture.checks.s3 import s3_buckets


def controls_for(ctx, bucket: str) -> set[str]:
    return {f.control_id for f in s3_buckets(ctx) if any(bucket in r.id for r in f.resources)}


def test_public_acl_bucket_is_flagged(ctx, aws):
    s3 = aws("s3")
    s3.create_bucket(Bucket="pub-acl")
    s3.put_bucket_acl(Bucket="pub-acl", ACL="public-read")

    assert "S3-001" in controls_for(ctx, "pub-acl")


def test_public_policy_bucket_is_flagged(ctx, aws):
    s3 = aws("s3")
    s3.create_bucket(Bucket="pub-policy")
    s3.put_bucket_policy(
        Bucket="pub-policy",
        Policy=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": "*",
                        "Action": "s3:GetObject",
                        "Resource": "arn:aws:s3:::pub-policy/*",
                    }
                ],
            }
        ),
    )

    assert "S3-001" in controls_for(ctx, "pub-policy")


def test_block_public_access_neutralizes_public_acl(ctx, aws):
    s3 = aws("s3")
    s3.create_bucket(Bucket="blocked")
    s3.put_bucket_acl(Bucket="blocked", ACL="public-read")
    s3.put_public_access_block(
        Bucket="blocked",
        PublicAccessBlockConfiguration={
            "BlockPublicAcls": True,
            "IgnorePublicAcls": True,
            "BlockPublicPolicy": True,
            "RestrictPublicBuckets": True,
        },
    )

    controls = controls_for(ctx, "blocked")
    assert "S3-001" not in controls  # BPA neutralizes the public ACL
    assert "S3-002" not in controls  # and BPA is fully enabled


def test_conditioned_wildcard_policy_is_not_public(ctx, aws):
    s3 = aws("s3")
    s3.create_bucket(Bucket="vpce-only")
    s3.put_bucket_policy(
        Bucket="vpce-only",
        Policy=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": "*",
                        "Action": "s3:GetObject",
                        "Resource": "arn:aws:s3:::vpce-only/*",
                        "Condition": {"StringEquals": {"aws:SourceVpce": "vpce-123"}},
                    }
                ],
            }
        ),
    )

    assert "S3-001" not in controls_for(ctx, "vpce-only")


def test_tls_enforcing_policy_clears_the_tls_control(ctx, aws):
    s3 = aws("s3")
    s3.create_bucket(Bucket="tls-ok")
    s3.put_bucket_policy(
        Bucket="tls-ok",
        Policy=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Deny",
                        "Principal": {"AWS": "*"},
                        "Action": "s3:*",
                        "Resource": "arn:aws:s3:::tls-ok/*",
                        "Condition": {"Bool": {"aws:SecureTransport": "false"}},
                    }
                ],
            }
        ),
    )

    assert "S3-004" not in controls_for(ctx, "tls-ok")
