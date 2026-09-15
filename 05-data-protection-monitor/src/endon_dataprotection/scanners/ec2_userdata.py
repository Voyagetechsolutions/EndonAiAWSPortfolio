"""Scan EC2 instance user data for secrets.

User data is a launch-time script, readable by anyone with `ec2:DescribeInstanceAttribute`
and by anything on the instance via the metadata service. Hard-coded credentials in user
data are a classic exposure, and one an SSRF against the metadata service can read.
"""

from __future__ import annotations

import base64
import binascii
from collections.abc import Iterator

from botocore.exceptions import ClientError

from endon_core.findings import Finding, Resource
from endon_dataprotection.context import ScanContext
from endon_dataprotection.scanners.base import describe_matches, max_severity, scanner


@scanner("EC2")
def ec2_user_data(ctx: ScanContext) -> Iterator[Finding]:
    ec2 = ctx.clients("ec2")
    for page in ec2.get_paginator("describe_instances").paginate():
        for reservation in page.get("Reservations", []):
            for instance in reservation.get("Instances", []):
                if instance.get("State", {}).get("Name") in ("terminated", "shutting-down"):
                    continue
                yield from _scan_instance(ctx, ec2, instance["InstanceId"])


def _scan_instance(ctx: ScanContext, ec2, instance_id: str) -> Iterator[Finding]:
    try:
        attr = ec2.describe_instance_attribute(InstanceId=instance_id, Attribute="userData")
    except ClientError:
        return
    encoded = (attr.get("UserData") or {}).get("Value")
    if not encoded:
        return
    text = _decode(encoded)
    matches = ctx.secrets.scan_text(text, location=f"ec2:{instance_id}/userData")
    if not matches:
        return
    resource = Resource(
        "AwsEc2Instance",
        f"arn:{ctx.partition}:ec2:{ctx.region}:{ctx.account_id}:instance/{instance_id}",
        region=ctx.region,
        details={"instanceId": instance_id},
    )
    yield ctx.finding(
        finding_type="DataProtection:EC2/SecretInUserData",
        title=f"Secret in EC2 user data: {instance_id}",
        severity=max_severity(matches),
        resource=resource,
        description=(
            f"Instance '{instance_id}' has {len(matches)} likely secret(s) in its user data. "
            f"{describe_matches(matches)}"
        ),
        remediation=(
            "Remove secrets from user data; fetch them at boot from Secrets Manager or SSM "
            "Parameter Store using the instance role, and rotate any exposed secret."
        ),
        control_id="DP-EC2-001",
        tags={
            "service": "EC2",
            "secretCount": str(len(matches)),
            "kinds": ",".join(sorted({m.kind for m in matches})),
        },
    )


def _decode(encoded: str) -> str:
    try:
        return base64.b64decode(encoded).decode("utf-8", "replace")
    except (binascii.Error, ValueError):
        return encoded
