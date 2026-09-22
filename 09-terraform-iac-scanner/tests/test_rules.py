"""Each rule predicate: fires on the bad shape, stays quiet on the good one."""

import json

from endon_tfscan import rules
from endon_tfscan.plan import Resource


def _res(resource_type: str, **values) -> Resource:
    return Resource(
        address=f"{resource_type}.x",
        type=resource_type,
        name="x",
        provider="aws",
        actions=("create",),
        values=values,
    )


def test_s3_public_acl():
    assert rules._s3_public_acl(_res("aws_s3_bucket", acl="public-read"))
    assert not rules._s3_public_acl(_res("aws_s3_bucket", acl="private"))


def test_s3_bpa_weak():
    assert rules._s3_bpa_weak(_res("aws_s3_bucket_public_access_block", block_public_acls=False))
    assert not rules._s3_bpa_weak(
        _res(
            "aws_s3_bucket_public_access_block",
            block_public_acls=True,
            block_public_policy=True,
            ignore_public_acls=True,
            restrict_public_buckets=True,
        )
    )


def test_s3_encryption_and_versioning():
    plain = _res("aws_s3_bucket", acl="private")
    assert rules._s3_no_encryption(plain)
    assert rules._s3_no_versioning(plain)
    encrypted = _res(
        "aws_s3_bucket",
        server_side_encryption_configuration=[{"rule": [{}]}],
        versioning=[{"enabled": True}],
    )
    assert not rules._s3_no_encryption(encrypted)
    assert not rules._s3_no_versioning(encrypted)


def test_security_group_admin_vs_other_port():
    admin = _res(
        "aws_security_group",
        ingress=[{"from_port": 22, "to_port": 22, "cidr_blocks": ["0.0.0.0/0"]}],
    )
    other = _res(
        "aws_security_group",
        ingress=[{"from_port": 8080, "to_port": 8080, "cidr_blocks": ["0.0.0.0/0"]}],
    )
    internal = _res(
        "aws_security_group",
        ingress=[{"from_port": 22, "to_port": 22, "cidr_blocks": ["10.0.0.0/8"]}],
    )
    assert rules._sg_admin_open(admin)
    assert not rules._sg_admin_open(other)
    assert rules._sg_open_non_admin(other)
    assert not rules._sg_open_non_admin(admin)
    assert not rules._sg_admin_open(internal)


def test_imds_ebs_rds():
    assert rules._imds_v1(_res("aws_instance", metadata_options=[{"http_tokens": "optional"}]))
    assert not rules._imds_v1(_res("aws_instance", metadata_options=[{"http_tokens": "required"}]))
    assert rules._ebs_unencrypted(_res("aws_ebs_volume", encrypted=False))
    assert not rules._ebs_unencrypted(_res("aws_ebs_volume", encrypted=True))
    assert rules._rds_unencrypted(_res("aws_db_instance", storage_encrypted=False))
    assert rules._rds_public(_res("aws_db_instance", publicly_accessible=True))


def test_iam_admin_and_passrole_reuse_project2():
    admin = _res(
        "aws_iam_policy",
        policy=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}],
            }
        ),
    )
    passrole = _res(
        "aws_iam_policy",
        policy=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [{"Effect": "Allow", "Action": "iam:PassRole", "Resource": "*"}],
            }
        ),
    )
    scoped = _res(
        "aws_iam_policy",
        policy=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {"Effect": "Allow", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::b/*"}
                ],
            }
        ),
    )
    assert rules._iam_admin(admin)
    assert not rules._iam_admin(scoped)
    assert rules._iam_unscoped_passrole(passrole)
    assert not rules._iam_unscoped_passrole(scoped)


def test_iam_malformed_policy_is_not_a_crash():
    assert not rules._iam_admin(_res("aws_iam_policy", policy="{not json"))
    assert not rules._iam_admin(_res("aws_iam_policy"))  # no policy attribute at all


def test_kms_and_cloudtrail():
    assert rules._kms_no_rotation(_res("aws_kms_key", enable_key_rotation=False))
    assert not rules._kms_no_rotation(_res("aws_kms_key", enable_key_rotation=True))
    assert rules._cloudtrail_weak(
        _res("aws_cloudtrail", is_multi_region_trail=False, kms_key_id="k")
    )
    assert rules._cloudtrail_weak(_res("aws_cloudtrail", is_multi_region_trail=True, kms_key_id=""))
    assert not rules._cloudtrail_weak(
        _res("aws_cloudtrail", is_multi_region_trail=True, kms_key_id="k")
    )
