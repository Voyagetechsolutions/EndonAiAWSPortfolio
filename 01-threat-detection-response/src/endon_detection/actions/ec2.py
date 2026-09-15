"""Isolate compromised EC2 instances without destroying evidence.

The instance is never stopped or terminated: memory, running processes and
disk state are evidence. Instead it is cut off from the network, protected
from termination, removed from its Auto Scaling group (which would otherwise
replace and terminate it), and handed to the forensics component.
"""

from __future__ import annotations

import json
from typing import Any

from botocore.exceptions import ClientError

from endon_core.aws import error_code
from endon_core.events import DetailType, Source
from endon_core.findings import Resource
from endon_core.incidents import ActionKind
from endon_detection.actions.base import Action, ActionContext, ActionOutcome, ActionSkipped
from endon_detection.actions.resources import incident_tags, instance_id

QUARANTINE_GROUP_NAME = "endon-quarantine"
TRANSITION_GROUP_NAME = "endon-quarantine-transition"
_TAG_VALUE_LIMIT = 256


class IsolateInstance(Action):
    name = "isolate_instance"
    kind = ActionKind.CONTAIN
    resource_types = ("AwsEc2Instance",)

    def plan(self, target: Resource, ctx: ActionContext) -> str:
        return (
            f"isolate EC2 instance {instance_id(target)}: detach from Auto Scaling, enable "
            "termination protection, move every network interface to a no-traffic security group"
        )

    def execute(self, target: Resource, ctx: ActionContext) -> ActionOutcome:
        ec2 = ctx.clients("ec2")
        iid = instance_id(target)
        instance = _describe_instance(ec2, iid)
        state = instance["State"]["Name"]
        if state in ("shutting-down", "terminated"):
            raise ActionSkipped(f"EC2 instance {iid} is already {state}")

        vpc_id = instance["VpcId"]
        original_groups = {
            eni["NetworkInterfaceId"]: [g["GroupId"] for g in eni.get("Groups", [])]
            for eni in instance.get("NetworkInterfaces", [])
        }
        quarantine_group = _ensure_quarantine_group(ec2, vpc_id)
        transition_group = _ensure_transition_group(ec2, vpc_id)

        # Detach first: an Auto Scaling health check would terminate the isolated
        # instance and destroy the evidence. A replacement keeps the service running.
        auto_scaling_group = _detach_from_auto_scaling(ctx, iid)
        ec2.modify_instance_attribute(InstanceId=iid, DisableApiTermination={"Value": True})

        for eni_id in original_groups:
            # Changing security groups does not interrupt *tracked* connections, so an
            # attacker's open shell would survive a direct switch to an empty group.
            # Traffic allowed from and to 0.0.0.0/0 on all ports is untracked; moving to
            # that group first and then to the empty group cuts existing sessions.
            ec2.modify_network_interface_attribute(
                NetworkInterfaceId=eni_id, Groups=[transition_group]
            )
            ec2.modify_network_interface_attribute(
                NetworkInterfaceId=eni_id, Groups=[quarantine_group]
            )

        original = json.dumps(original_groups, separators=(",", ":"))
        tags = incident_tags(ctx.incident.incident_id, "QUARANTINED")
        tags.append(
            {
                "Key": "endon:original-security-groups",
                "Value": original if len(original) <= _TAG_VALUE_LIMIT else "see incident record",
            }
        )
        ec2.create_tags(Resources=[iid], Tags=tags)

        return ActionOutcome(
            f"Isolated EC2 instance {iid} in quarantine security group {quarantine_group}",
            {
                "instanceId": iid,
                "vpcId": vpc_id,
                "quarantineSecurityGroupId": quarantine_group,
                "originalSecurityGroups": original_groups,
                "detachedFromAutoScalingGroup": auto_scaling_group,
                "terminationProtection": True,
                "iamInstanceProfileArn": (instance.get("IamInstanceProfile") or {}).get("Arn"),
            },
        )


class RequestForensics(Action):
    name = "request_forensics"
    kind = ActionKind.EVIDENCE
    resource_types = ("AwsEc2Instance",)

    def plan(self, target: Resource, ctx: ActionContext) -> str:
        return f"request forensic evidence collection for EC2 instance {instance_id(target)}"

    def execute(self, target: Resource, ctx: ActionContext) -> ActionOutcome:
        finding, incident = ctx.finding, ctx.incident
        detail = {
            "incidentId": incident.incident_id,
            "findingId": finding.id,
            "findingType": finding.type,
            "severity": finding.severity.value,
            "accountId": finding.account_id,
            "region": finding.region,
            "instanceId": instance_id(target),
            "instanceArn": target.id,
        }
        ctx.publisher.publish(
            Source.DETECTION, DetailType.FORENSICS_REQUESTED, detail, resources=[target.id]
        )
        return ActionOutcome(f"Forensics requested for EC2 instance {instance_id(target)}", detail)


class TagForReview(Action):
    name = "tag_for_review"
    kind = ActionKind.EVIDENCE
    resource_types = ("AwsEc2Instance", "AwsIamUser", "AwsIamRole")

    def plan(self, target: Resource, ctx: ActionContext) -> str:
        return f"tag {target.type} {target.name} for security review"

    def execute(self, target: Resource, ctx: ActionContext) -> ActionOutcome:
        tags = incident_tags(ctx.incident.incident_id, "REVIEW_REQUIRED")
        if target.type == "AwsEc2Instance":
            ctx.clients("ec2").create_tags(Resources=[instance_id(target)], Tags=tags)
        elif target.type == "AwsIamUser":
            ctx.clients("iam").tag_user(
                UserName=target.details.get("userName") or target.name, Tags=tags
            )
        else:
            ctx.clients("iam").tag_role(
                RoleName=target.details.get("roleName") or target.name, Tags=tags
            )
        return ActionOutcome(f"Tagged {target.type} {target.name} for security review")


def _describe_instance(ec2: Any, iid: str) -> dict[str, Any]:
    reservations = ec2.describe_instances(InstanceIds=[iid])["Reservations"]
    instances = [i for r in reservations for i in r["Instances"]]
    if not instances:
        raise ActionSkipped(f"EC2 instance {iid} was not found")
    return instances[0]


def _find_group(ec2: Any, vpc_id: str, name: str) -> dict[str, Any] | None:
    groups = ec2.describe_security_groups(
        Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "group-name", "Values": [name]}]
    )["SecurityGroups"]
    return groups[0] if groups else None


def _create_group(ec2: Any, vpc_id: str, name: str, description: str) -> tuple[str, bool]:
    """Create the group, tolerating a concurrent responder creating it first."""
    try:
        group_id = ec2.create_security_group(
            GroupName=name,
            Description=description,
            VpcId=vpc_id,
            TagSpecifications=[
                {
                    "ResourceType": "security-group",
                    "Tags": [{"Key": "endon:purpose", "Value": "incident-isolation"}],
                }
            ],
        )["GroupId"]
        return group_id, True
    except ClientError as exc:
        if error_code(exc) != "InvalidGroup.Duplicate":
            raise
        existing = _find_group(ec2, vpc_id, name)
        if existing is None:
            raise
        return existing["GroupId"], False


def _ensure_quarantine_group(ec2: Any, vpc_id: str) -> str:
    group = _find_group(ec2, vpc_id, QUARANTINE_GROUP_NAME)
    if group is None:
        group_id, _ = _create_group(
            ec2, vpc_id, QUARANTINE_GROUP_NAME, "Endon AI incident isolation - no traffic allowed"
        )
        group = _find_group(ec2, vpc_id, QUARANTINE_GROUP_NAME) or {"GroupId": group_id}
    # Re-verify on every use: a rule added to this group by anyone would silently
    # reopen every quarantined instance in the VPC.
    if group.get("IpPermissions"):
        ec2.revoke_security_group_ingress(
            GroupId=group["GroupId"], IpPermissions=group["IpPermissions"]
        )
    if group.get("IpPermissionsEgress"):
        ec2.revoke_security_group_egress(
            GroupId=group["GroupId"], IpPermissions=group["IpPermissionsEgress"]
        )
    return group["GroupId"]


def _ensure_transition_group(ec2: Any, vpc_id: str) -> str:
    group = _find_group(ec2, vpc_id, TRANSITION_GROUP_NAME)
    if group is not None:
        return group["GroupId"]
    group_id, created = _create_group(
        ec2,
        vpc_id,
        TRANSITION_GROUP_NAME,
        "Endon AI isolation step - makes existing flows untracked so isolation cuts them",
    )
    if created:
        ec2.authorize_security_group_ingress(
            GroupId=group_id,
            IpPermissions=[
                {
                    "IpProtocol": "-1",
                    "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                    "Ipv6Ranges": [{"CidrIpv6": "::/0"}],
                }
            ],
        )
    return group_id


def _detach_from_auto_scaling(ctx: ActionContext, iid: str) -> str | None:
    autoscaling = ctx.clients("autoscaling")
    members = autoscaling.describe_auto_scaling_instances(InstanceIds=[iid])["AutoScalingInstances"]
    if not members:
        return None
    group = members[0]["AutoScalingGroupName"]
    autoscaling.detach_instances(
        InstanceIds=[iid], AutoScalingGroupName=group, ShouldDecrementDesiredCapacity=False
    )
    return group
