import json

from detection_testkit import ACCOUNT_ID, REGION, describe_instance, instance_resource
from endon_core.events import DetailType
from endon_core.incidents import IncidentStatus
from endon_detection import samples
from endon_detection.actions.ec2 import QUARANTINE_GROUP_NAME


def quarantine_group(aws, vpc_id):
    return aws("ec2").describe_security_groups(
        Filters=[
            {"Name": "vpc-id", "Values": [vpc_id]},
            {"Name": "group-name", "Values": [QUARANTINE_GROUP_NAME]},
        ]
    )["SecurityGroups"][0]


def eni_groups(aws, eni_id):
    """Security groups set on the network interface itself.

    moto reports an attached interface's groups as the union of its own groups and the
    instance's launch-time groups, whereas EC2 replaces the set on modification. The
    group-id filter reads the interface's own set - the one ModifyNetworkInterfaceAttribute changes.
    """
    ec2 = aws("ec2")
    return sorted(
        group["GroupId"]
        for group in ec2.describe_security_groups()["SecurityGroups"]
        if any(
            eni["NetworkInterfaceId"] == eni_id
            for eni in ec2.describe_network_interfaces(
                Filters=[{"Name": "group-id", "Values": [group["GroupId"]]}]
            )["NetworkInterfaces"]
        )
    )


def instance_tags(aws, instance_id):
    instance = aws("ec2").describe_instances(InstanceIds=[instance_id])["Reservations"][0][
        "Instances"
    ][0]
    return {t["Key"]: t["Value"] for t in instance.get("Tags", [])}


def test_compromised_instance_is_isolated_and_evidence_preserved(aws, engine, bus, ec2_instance):
    event = samples.ec2_cryptomining(ACCOUNT_ID, REGION, instance_resource(ec2_instance))

    [incident] = engine.handle_event(event)

    assert incident.playbook == "compromised-ec2"
    assert incident.status is IncidentStatus.CONTAINED

    ec2 = aws("ec2")
    group = quarantine_group(aws, ec2_instance["vpc_id"])
    assert eni_groups(aws, ec2_instance["eni_id"]) == [group["GroupId"]]
    assert group["IpPermissions"] == []
    assert group["IpPermissionsEgress"] == []

    instance_id = ec2_instance["instance_id"]
    protection = ec2.describe_instance_attribute(
        InstanceId=instance_id, Attribute="disableApiTermination"
    )
    assert protection["DisableApiTermination"]["Value"] is True
    state = ec2.describe_instances(InstanceIds=[instance_id])["Reservations"][0]["Instances"][0][
        "State"
    ]["Name"]
    assert state == "running"  # never stopped: memory is evidence

    tags = instance_tags(aws, instance_id)
    assert tags["endon:incident-status"] == "QUARANTINED"
    assert json.loads(tags["endon:original-security-groups"]) == {
        ec2_instance["eni_id"]: ec2_instance["group_ids"]
    }

    [request] = bus.events(DetailType.FORENSICS_REQUESTED)
    assert request["detail"]["instanceId"] == instance_id


def test_instance_is_detached_from_auto_scaling_before_isolation(aws, engine, network):
    aws("ec2").create_launch_template(
        LaunchTemplateName="web",
        LaunchTemplateData={"ImageId": network["image_id"], "InstanceType": "t3.micro"},
    )
    autoscaling = aws("autoscaling")
    autoscaling.create_auto_scaling_group(
        AutoScalingGroupName="web-asg",
        LaunchTemplate={"LaunchTemplateName": "web"},
        MinSize=1,
        MaxSize=2,
        DesiredCapacity=1,
        VPCZoneIdentifier=network["subnet_id"],
    )
    group = autoscaling.describe_auto_scaling_groups(AutoScalingGroupNames=["web-asg"])[
        "AutoScalingGroups"
    ][0]
    instance = describe_instance(aws, group["Instances"][0]["InstanceId"])

    [incident] = engine.handle_event(
        samples.ec2_cryptomining(ACCOUNT_ID, REGION, instance_resource(instance))
    )

    assert incident.status is IncidentStatus.CONTAINED
    members = autoscaling.describe_auto_scaling_instances(InstanceIds=[instance["instance_id"]])
    assert members["AutoScalingInstances"] == []
    isolate = next(a for a in incident.actions if a.action == "isolate_instance")
    assert isolate.data["detachedFromAutoScalingGroup"] == "web-asg"


def test_tampered_quarantine_group_is_reset(aws, engine, ec2_instance):
    ec2 = aws("ec2")
    tampered = ec2.create_security_group(
        GroupName=QUARANTINE_GROUP_NAME, Description="tampered", VpcId=ec2_instance["vpc_id"]
    )["GroupId"]
    ec2.authorize_security_group_ingress(
        GroupId=tampered,
        IpPermissions=[
            {
                "IpProtocol": "tcp",
                "FromPort": 22,
                "ToPort": 22,
                "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
            }
        ],
    )

    engine.handle_event(
        samples.ec2_cryptomining(ACCOUNT_ID, REGION, instance_resource(ec2_instance))
    )

    group = quarantine_group(aws, ec2_instance["vpc_id"])
    assert group["GroupId"] == tampered
    assert group["IpPermissions"] == []
    assert group["IpPermissionsEgress"] == []


def test_probed_instance_is_flagged_not_isolated(aws, engine, ec2_instance):
    [incident] = engine.handle_event(
        samples.port_probe(ACCOUNT_ID, REGION, instance_resource(ec2_instance))
    )

    assert incident.playbook == "exposed-ec2"
    assert incident.status is IncidentStatus.MONITORING
    assert eni_groups(aws, ec2_instance["eni_id"]) == ec2_instance["group_ids"]
    assert (
        instance_tags(aws, ec2_instance["instance_id"])["endon:incident-status"]
        == "REVIEW_REQUIRED"
    )


def test_protected_instance_is_not_isolated(aws, engine, bus, ec2_instance):
    aws("ec2").create_tags(
        Resources=[ec2_instance["instance_id"]], Tags=[{"Key": "endon:protected", "Value": "true"}]
    )

    [incident] = engine.handle_event(
        samples.ec2_cryptomining(ACCOUNT_ID, REGION, instance_resource(ec2_instance))
    )

    assert incident.status is IncidentStatus.SUPPRESSED
    assert eni_groups(aws, ec2_instance["eni_id"]) == ec2_instance["group_ids"]
    # Evidence collection still goes ahead for a protected host.
    assert len(bus.events(DetailType.FORENSICS_REQUESTED)) == 1
