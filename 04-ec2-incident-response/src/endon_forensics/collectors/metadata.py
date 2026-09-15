"""Capture the instance's full configuration as evidence (stable, but foundational)."""

from __future__ import annotations

from endon_forensics.collectors.base import Collector, CollectorContext
from endon_forensics.models import EvidenceItem, EvidenceStatus


class MetadataCollector(Collector):
    id = "instance-metadata"
    kind = "metadata"
    order = 20
    critical = True

    def collect(self, ctx: CollectorContext) -> list[EvidenceItem]:
        ec2 = ctx.clients("ec2")
        instance_id = ctx.case.instance_id
        reservations = ec2.describe_instances(InstanceIds=[instance_id])["Reservations"]
        instances = [i for r in reservations for i in r["Instances"]]
        if not instances:
            return [
                EvidenceItem(
                    id=self.id,
                    kind=self.kind,
                    description="EC2 instance configuration and state",
                    status=EvidenceStatus.FAILED,
                    collector=self.id,
                    detail={"error": "instance not found"},
                )
            ]
        instance = instances[0]

        volumes = _attached_volumes(ec2, instance)
        record = {
            "instance": instance,
            "attachedVolumes": volumes,
            "networkInterfaces": instance.get("NetworkInterfaces", []),
            "iamInstanceProfile": instance.get("IamInstanceProfile"),
            "tags": instance.get("Tags", []),
        }
        stored = ctx.store.put_json(ctx.case.case_id, "instance-metadata.json", record)
        return [
            EvidenceItem(
                id=self.id,
                kind=self.kind,
                description="EC2 instance configuration, network interfaces, IAM profile and volumes",
                status=EvidenceStatus.COLLECTED,
                collector=self.id,
                s3_key=stored.key,
                sha256=stored.sha256,
                size_bytes=stored.size_bytes,
                detail={
                    "instanceType": instance.get("InstanceType"),
                    "state": instance.get("State", {}).get("Name"),
                    "imageId": instance.get("ImageId"),
                    "volumeCount": len(volumes),
                    "iamInstanceProfileArn": (instance.get("IamInstanceProfile") or {}).get("Arn"),
                },
            )
        ]


def _attached_volumes(ec2, instance: dict) -> list[dict]:
    volume_ids = [
        m["Ebs"]["VolumeId"]
        for m in instance.get("BlockDeviceMappings", [])
        if m.get("Ebs", {}).get("VolumeId")
    ]
    if not volume_ids:
        return []
    return ec2.describe_volumes(VolumeIds=volume_ids)["Volumes"]
