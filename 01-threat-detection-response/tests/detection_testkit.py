"""Shared constants and helpers for the detection and response tests."""

from endon_detection import samples

REGION = "us-east-1"
ACCOUNT_ID = "123456789012"  # moto's default account


def describe_instance(aws, instance_id):
    instance = aws("ec2").describe_instances(InstanceIds=[instance_id])["Reservations"][0][
        "Instances"
    ][0]
    eni = instance["NetworkInterfaces"][0]
    return {
        "instance_id": instance_id,
        "vpc_id": instance["VpcId"],
        "subnet_id": instance["SubnetId"],
        "eni_id": eni["NetworkInterfaceId"],
        "group_ids": [g["GroupId"] for g in eni["Groups"]],
    }


def instance_resource(instance):
    return samples.instance_resource(
        instance["instance_id"],
        vpc_id=instance["vpc_id"],
        subnet_id=instance["subnet_id"],
        network_interface_id=instance["eni_id"],
        security_group_ids=instance["group_ids"],
    )
