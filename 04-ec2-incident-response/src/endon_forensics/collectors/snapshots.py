"""Snapshot every attached EBS volume — the disk evidence.

Snapshots are point-in-time copies taken without touching the running instance, tagged
with the incident id so they are traceable, and left in place (never deleted). A snapshot
of an encrypted volume is itself encrypted.
"""

from __future__ import annotations

from endon_core.timeutil import isoformat, utc_now
from endon_forensics.collectors.base import Collector, CollectorContext
from endon_forensics.models import EvidenceItem, EvidenceStatus


class DiskSnapshotCollector(Collector):
    id = "ebs-snapshots"
    kind = "disk-snapshot"
    order = 50  # least volatile: disk state is captured last
    critical = True

    def collect(self, ctx: CollectorContext) -> list[EvidenceItem]:
        ec2 = ctx.clients("ec2")
        case = ctx.case
        instance = _describe(ec2, case.instance_id)
        if instance is None:
            return [self._failed("instance not found")]

        volume_ids = [
            m["Ebs"]["VolumeId"]
            for m in instance.get("BlockDeviceMappings", [])
            if m.get("Ebs", {}).get("VolumeId")
        ]
        if not volume_ids:
            return [
                EvidenceItem(
                    id=self.id,
                    kind=self.kind,
                    description="EBS volume snapshots",
                    status=EvidenceStatus.SKIPPED,
                    collector=self.id,
                    detail={"reason": "instance has no attached EBS volumes"},
                )
            ]

        items: list[EvidenceItem] = []
        for volume_id in volume_ids:
            items.append(self._snapshot(ec2, ctx, volume_id))
        return items

    def _snapshot(self, ec2, ctx: CollectorContext, volume_id: str) -> EvidenceItem:
        case = ctx.case
        result = ec2.create_snapshot(
            VolumeId=volume_id,
            Description=f"Endon forensic evidence for incident {case.incident_id} / instance {case.instance_id}",
        )
        snapshot_id = result["SnapshotId"]
        ec2.create_tags(
            Resources=[snapshot_id],
            Tags=[
                {"Key": "endon:evidence", "Value": "true"},
                {"Key": "endon:incident-id", "Value": case.incident_id},
                {"Key": "endon:source-instance", "Value": case.instance_id},
                {"Key": "endon:source-volume", "Value": volume_id},
                {"Key": "endon:collected-at", "Value": isoformat(utc_now(), "seconds")},
            ],
        )
        # The snapshot itself lives in EC2; record its identity and integrity metadata as evidence.
        stored = ctx.store.put_json(
            case.case_id,
            f"snapshot-{volume_id}.json",
            {
                "volumeId": volume_id,
                "snapshotId": snapshot_id,
                "encrypted": result.get("Encrypted"),
            },
        )
        return EvidenceItem(
            id=f"ebs-snapshot-{volume_id}",
            kind=self.kind,
            description=f"EBS snapshot of volume {volume_id}",
            status=EvidenceStatus.COLLECTED,
            collector=self.id,
            s3_key=stored.key,
            sha256=stored.sha256,
            size_bytes=stored.size_bytes,
            detail={
                "volumeId": volume_id,
                "snapshotId": snapshot_id,
                "encrypted": result.get("Encrypted"),
            },
        )

    def _failed(self, reason: str) -> EvidenceItem:
        return EvidenceItem(
            id=self.id,
            kind=self.kind,
            description="EBS volume snapshots",
            status=EvidenceStatus.FAILED,
            collector=self.id,
            detail={"error": reason},
        )


def _describe(ec2, instance_id: str) -> dict | None:
    reservations = ec2.describe_instances(InstanceIds=[instance_id])["Reservations"]
    instances = [i for r in reservations for i in r["Instances"]]
    return instances[0] if instances else None
