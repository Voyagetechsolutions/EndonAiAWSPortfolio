"""EC2 and networking posture: open security groups, unencrypted EBS, IMDSv2."""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any

from endon_core.findings import Finding, Resource
from endon_posture.checks.base import (
    check,
    permission_is_all_protocols,
    permission_is_open_to_internet,
    permission_matches_port,
)
from endon_posture.context import ScanContext


@check("EC2")
def security_groups(ctx: ScanContext) -> Iterator[Finding]:
    ec2 = ctx.clients("ec2")
    for group in _paginate(ec2, "describe_security_groups", "SecurityGroups"):
        resource = Resource(
            "AwsEc2SecurityGroup",
            f"arn:{ctx.partition}:ec2:{ctx.region}:{ctx.account_id}:security-group/{group['GroupId']}",
            region=ctx.region,
            details={"groupId": group["GroupId"], "groupName": group.get("GroupName")},
        )
        ingress = group.get("IpPermissions", [])
        open_rules = [p for p in ingress if permission_is_open_to_internet(p)]

        if any(permission_is_all_protocols(p) for p in open_rules):
            yield ctx.finding("EC2-003", resource)
        else:
            if any(permission_matches_port(p, 22) for p in open_rules):
                yield ctx.finding("EC2-001", resource)
            if any(permission_matches_port(p, 3389) for p in open_rules):
                yield ctx.finding("EC2-002", resource)

        if group.get("GroupName") == "default" and (ingress or group.get("IpPermissionsEgress")):
            yield ctx.finding("EC2-004", resource, detail=f"VPC {group.get('VpcId', 'unknown')}.")


@check("EC2")
def ebs_volumes(ctx: ScanContext) -> Iterator[Finding]:
    ec2 = ctx.clients("ec2")
    for volume in _paginate(ec2, "describe_volumes", "Volumes"):
        if not volume.get("Encrypted", False):
            resource = Resource(
                "AwsEc2Volume",
                f"arn:{ctx.partition}:ec2:{ctx.region}:{ctx.account_id}:volume/{volume['VolumeId']}",
                region=ctx.region,
                details={"volumeId": volume["VolumeId"]},
            )
            yield ctx.finding("EC2-005", resource)

    if not ec2.get_ebs_encryption_by_default().get("EbsEncryptionByDefault", False):
        yield ctx.finding("EC2-006", ctx.account_resource())


@check("EC2")
def instance_metadata(ctx: ScanContext) -> Iterator[Finding]:
    ec2 = ctx.clients("ec2")
    for reservation in _paginate(ec2, "describe_instances", "Reservations"):
        for instance in reservation.get("Instances", []):
            if instance.get("State", {}).get("Name") in ("terminated", "shutting-down"):
                continue
            options = instance.get("MetadataOptions") or {}
            if options.get("HttpTokens", "optional") != "required":
                resource = Resource(
                    "AwsEc2Instance",
                    f"arn:{ctx.partition}:ec2:{ctx.region}:{ctx.account_id}:instance/{instance['InstanceId']}",
                    region=ctx.region,
                    details={"instanceId": instance["InstanceId"]},
                )
                yield ctx.finding("EC2-007", resource)


def _paginate(client: Any, operation: str, key: str) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    paginator = client.get_paginator(operation)
    for page in paginator.paginate():
        items.extend(page.get(key, []))
    return items
