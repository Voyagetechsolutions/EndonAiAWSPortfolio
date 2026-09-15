"""Collect volatile in-memory state via SSM — processes, connections, logged-in users.

This is the most volatile evidence and is collected first. It also exposes a real forensic
trade-off: a properly isolated instance (moved to a no-traffic security group) cannot reach
the SSM endpoints, so live response is only possible if the quarantine design allows egress
to the SSM VPC endpoints. When the instance is not reachable via SSM, this is recorded as
SKIPPED with the reason, rather than silently omitted — an honest gap in the evidence.
"""

from __future__ import annotations

import time

from botocore.exceptions import ClientError

from endon_forensics.collectors.base import Collector, CollectorContext
from endon_forensics.models import EvidenceItem, EvidenceStatus

# Read-only live-response commands. Nothing here modifies the host.
LIVE_RESPONSE_COMMANDS = [
    "date -u",
    "uname -a",
    "ps auxww",
    "ss -tunap || netstat -tunap",
    "who -a",
    "last -20",
    "ls -la /tmp /var/tmp /dev/shm",
    "crontab -l 2>/dev/null; ls -la /etc/cron*",
]
_POLL_ATTEMPTS = 20


class VolatileDataCollector(Collector):
    id = "volatile-data"
    kind = "volatile"
    order = 10  # most volatile: collected first

    def collect(self, ctx: CollectorContext) -> list[EvidenceItem]:
        ssm = ctx.clients("ssm")
        instance_id = ctx.case.instance_id
        if not _is_ssm_managed(ssm, instance_id):
            return [
                EvidenceItem(
                    id=self.id,
                    kind=self.kind,
                    description="Volatile state (processes, network connections, sessions) via SSM",
                    status=EvidenceStatus.SKIPPED,
                    collector=self.id,
                    detail={
                        "reason": "instance is not reachable via SSM (isolated, or SSM agent absent); "
                        "volatile memory is not collectable without relaxing network isolation"
                    },
                )
            ]

        command_id = ssm.send_command(
            InstanceIds=[instance_id],
            DocumentName="AWS-RunShellScript",
            Comment=f"Endon forensic live response for incident {ctx.case.incident_id}",
            Parameters={"commands": LIVE_RESPONSE_COMMANDS},
        )["Command"]["CommandId"]

        output = _await_output(ssm, command_id, instance_id)
        if output is None:
            return [
                EvidenceItem(
                    id=self.id,
                    kind=self.kind,
                    description="Volatile state via SSM",
                    status=EvidenceStatus.FAILED,
                    collector=self.id,
                    detail={"reason": "SSM command did not complete", "commandId": command_id},
                )
            ]

        stored = ctx.store.put(
            ctx.case.case_id, "volatile-data.txt", output.encode("utf-8"), "text/plain"
        )
        return [
            EvidenceItem(
                id=self.id,
                kind=self.kind,
                description="Volatile state (processes, network connections, sessions, cron) via SSM",
                status=EvidenceStatus.COLLECTED,
                collector=self.id,
                s3_key=stored.key,
                sha256=stored.sha256,
                size_bytes=stored.size_bytes,
                detail={"commandId": command_id},
            )
        ]


def _is_ssm_managed(ssm, instance_id: str) -> bool:
    try:
        info = ssm.describe_instance_information(
            Filters=[{"Key": "InstanceIds", "Values": [instance_id]}]
        )
        return bool(info.get("InstanceInformationList"))
    except Exception:
        # No SSM access, or SSM not available here: the host is not reachable for live response.
        return False


def _await_output(ssm, command_id: str, instance_id: str) -> str | None:
    for _ in range(_POLL_ATTEMPTS):
        try:
            result = ssm.get_command_invocation(CommandId=command_id, InstanceId=instance_id)
        except ClientError:
            time.sleep(1)
            continue
        status = result.get("Status")
        if status in ("Success", "Failed", "TimedOut", "Cancelled"):
            return (result.get("StandardOutputContent") or "") + (
                result.get("StandardErrorContent") or ""
            )
        time.sleep(1)
    return None
