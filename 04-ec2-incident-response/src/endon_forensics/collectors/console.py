"""Capture the instance console output (and screenshot where available)."""

from __future__ import annotations

import base64
import binascii

from endon_forensics.collectors.base import Collector, CollectorContext
from endon_forensics.models import EvidenceItem, EvidenceStatus


class ConsoleCollector(Collector):
    id = "console-output"
    kind = "console"
    order = 30

    def collect(self, ctx: CollectorContext) -> list[EvidenceItem]:
        items = [self._console_output(ctx)]
        screenshot = self._console_screenshot(ctx)
        if screenshot is not None:
            items.append(screenshot)
        return items

    def _console_output(self, ctx: CollectorContext) -> EvidenceItem:
        ec2 = ctx.clients("ec2")
        response = ec2.get_console_output(InstanceId=ctx.case.instance_id)
        text = _decode(response.get("Output", ""))
        if not text:
            return EvidenceItem(
                id=self.id,
                kind=self.kind,
                description="EC2 serial console output",
                status=EvidenceStatus.SKIPPED,
                collector=self.id,
                detail={"reason": "no console output available yet"},
            )
        stored = ctx.store.put(
            ctx.case.case_id, "console-output.txt", text.encode("utf-8"), "text/plain"
        )
        return EvidenceItem(
            id=self.id,
            kind=self.kind,
            description="EC2 serial console output",
            status=EvidenceStatus.COLLECTED,
            collector=self.id,
            s3_key=stored.key,
            sha256=stored.sha256,
            size_bytes=stored.size_bytes,
        )

    def _console_screenshot(self, ctx: CollectorContext) -> EvidenceItem | None:
        ec2 = ctx.clients("ec2")
        try:
            response = ec2.get_console_screenshot(InstanceId=ctx.case.instance_id)
        except Exception:
            # Best-effort: not all instance types support it, and it is absent from some
            # environments. A missing screenshot must not lose the console text evidence.
            return None
        image_b64 = response.get("ImageData")
        if not image_b64:
            return None
        try:
            image = base64.b64decode(image_b64)
        except (binascii.Error, ValueError):
            return None
        stored = ctx.store.put(ctx.case.case_id, "console-screenshot.jpg", image, "image/jpeg")
        return EvidenceItem(
            id="console-screenshot",
            kind=self.kind,
            description="EC2 console screenshot",
            status=EvidenceStatus.COLLECTED,
            collector=self.id,
            s3_key=stored.key,
            sha256=stored.sha256,
            size_bytes=stored.size_bytes,
        )


def _decode(output: str) -> str:
    """GetConsoleOutput returns base64 in real AWS; some emulators return plain text."""
    if not output:
        return ""
    try:
        return base64.b64decode(output, validate=True).decode("utf-8", "replace")
    except (binascii.Error, ValueError):
        return output
