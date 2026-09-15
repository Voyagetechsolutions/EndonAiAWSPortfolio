"""Shared setup for the forensics tests and the offline simulation.

Builds an *isolated* compromised instance — the state Project 1 leaves a host in
(quarantine security group, termination protection) — plus an Object Lock evidence
bucket, and the ``Endon Forensics Requested`` event Project 1 publishes.
"""

from __future__ import annotations

import uuid

from endon_core.events import DetailType, Source
from endon_core.timeutil import isoformat, utc_now

REGION = "us-east-1"
ACCOUNT_ID = "123456789012"
EVIDENCE_BUCKET = "endon-evidence-forensics-test"
QUARANTINE_GROUP = "endon-quarantine"


def create_evidence_bucket(aws, name: str = EVIDENCE_BUCKET) -> str:
    s3 = aws("s3")
    s3.create_bucket(Bucket=name, ObjectLockEnabledForBucket=True)
    s3.put_object_lock_configuration(
        Bucket=name,
        ObjectLockConfiguration={
            "ObjectLockEnabled": "Enabled",
            "Rule": {"DefaultRetention": {"Mode": "GOVERNANCE", "Days": 90}},
        },
    )
    return name


def isolated_instance(aws, *, contained: bool = True) -> dict:
    """An EC2 instance with an attached volume, isolated the way Project 1 leaves it."""
    ec2 = aws("ec2")
    vpc = ec2.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]["VpcId"]
    subnet = ec2.create_subnet(VpcId=vpc, CidrBlock="10.0.1.0/24")["Subnet"]["SubnetId"]
    group_name = QUARANTINE_GROUP if contained else "web"
    sg = ec2.create_security_group(GroupName=group_name, Description=group_name, VpcId=vpc)[
        "GroupId"
    ]
    image = ec2.describe_images(Owners=["amazon"])["Images"][0]["ImageId"]
    instance = ec2.run_instances(
        ImageId=image,
        MinCount=1,
        MaxCount=1,
        InstanceType="t3.micro",
        SubnetId=subnet,
        SecurityGroupIds=[sg],
        TagSpecifications=[
            {"ResourceType": "instance", "Tags": [{"Key": "Name", "Value": "web-01"}]}
        ],
    )["Instances"][0]
    instance_id = instance["InstanceId"]
    if contained:
        ec2.modify_instance_attribute(InstanceId=instance_id, DisableApiTermination={"Value": True})

    described = ec2.describe_instances(InstanceIds=[instance_id])["Reservations"][0]["Instances"][0]
    volume_ids = [
        m["Ebs"]["VolumeId"] for m in described.get("BlockDeviceMappings", []) if m.get("Ebs")
    ]
    return {
        "instance_id": instance_id,
        "instance_arn": f"arn:aws:ec2:{REGION}:{ACCOUNT_ID}:instance/{instance_id}",
        "vpc": vpc,
        "subnet": subnet,
        "security_group": sg,
        "volume_ids": volume_ids,
    }


def forensics_request(instance: dict, *, incident_id: str = "INC-TESTCASE01") -> dict:
    detail = {
        "incidentId": incident_id,
        "findingId": "gd-finding-1",
        "findingType": "CryptoCurrency:EC2/BitcoinTool.B!DNS",
        "severity": "HIGH",
        "accountId": ACCOUNT_ID,
        "region": REGION,
        "instanceId": instance["instance_id"],
        "instanceArn": instance["instance_arn"],
    }
    return {
        "version": "0",
        "id": str(uuid.uuid4()),
        "detail-type": DetailType.FORENSICS_REQUESTED,
        "source": Source.DETECTION,
        "account": ACCOUNT_ID,
        "time": isoformat(utc_now(), "seconds"),
        "region": REGION,
        "resources": [instance["instance_arn"]],
        "detail": detail,
    }
