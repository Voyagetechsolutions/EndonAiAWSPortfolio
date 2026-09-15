"""Detective-control posture: GuardDuty and AWS Config must be on."""

from __future__ import annotations

from collections.abc import Iterator

from endon_core.findings import Finding
from endon_posture.checks.base import check
from endon_posture.context import ScanContext


@check("GuardDuty")
def guardduty_enabled(ctx: ScanContext) -> Iterator[Finding]:
    detectors = ctx.clients("guardduty").list_detectors().get("DetectorIds", [])
    if not detectors:
        yield ctx.finding("DET-001", ctx.account_resource())


@check("Config")
def config_recording(ctx: ScanContext) -> Iterator[Finding]:
    config = ctx.clients("config")
    statuses = config.describe_configuration_recorder_status().get(
        "ConfigurationRecordersStatus", []
    )
    if not any(status.get("recording") for status in statuses):
        yield ctx.finding("DET-002", ctx.account_resource())
