"""Verify (never change) the containment state of the instance under investigation.

Project 1 isolates a compromised instance; this component records whether that isolation
is actually in place at collection time, as part of the evidence. It does not re-isolate —
containment is the response engine's job — but a case where the host was *not* contained
is important to flag.
"""

from __future__ import annotations

from typing import Any

from botocore.exceptions import ClientError

from endon_core.aws import error_code

QUARANTINE_GROUP_NAME = "endon-quarantine"


def verify_isolation(clients, instance_id: str) -> dict[str, Any]:
    ec2 = clients("ec2")
    try:
        reservations = ec2.describe_instances(InstanceIds=[instance_id])["Reservations"]
    except ClientError as exc:
        return {"contained": False, "error": error_code(exc) or str(exc)}
    instances = [i for r in reservations for i in r["Instances"]]
    if not instances:
        return {"contained": False, "error": "instance not found"}
    instance = instances[0]

    groups = [g.get("GroupName") for g in instance.get("SecurityGroups", [])]
    in_quarantine = groups == [QUARANTINE_GROUP_NAME]
    termination_protected = _termination_protection(ec2, instance_id)
    in_asg = _in_auto_scaling_group(clients, instance_id)
    state = instance.get("State", {}).get("Name")

    contained = in_quarantine and termination_protected and not in_asg and state == "running"
    notes = []
    if not in_quarantine:
        notes.append(f"security groups are {groups}, expected only {QUARANTINE_GROUP_NAME}")
    if not termination_protected:
        notes.append("termination protection is off")
    if in_asg:
        notes.append("still a member of an Auto Scaling group")
    if state != "running":
        notes.append(
            f"instance state is {state}; a stopped/terminated host loses volatile evidence"
        )

    return {
        "contained": contained,
        "state": state,
        "securityGroups": groups,
        "terminationProtection": termination_protected,
        "inAutoScalingGroup": in_asg,
        "notes": notes,
    }


def _termination_protection(ec2, instance_id: str) -> bool:
    try:
        attr = ec2.describe_instance_attribute(
            InstanceId=instance_id, Attribute="disableApiTermination"
        )
        return bool(attr["DisableApiTermination"]["Value"])
    except ClientError:
        return False


def _in_auto_scaling_group(clients, instance_id: str) -> bool:
    try:
        members = clients("autoscaling").describe_auto_scaling_instances(InstanceIds=[instance_id])
        return bool(members.get("AutoScalingInstances"))
    except ClientError:
        return False
