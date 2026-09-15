"""Runtime settings, read from environment variables set by the CDK stacks."""

from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum

from endon_core.events import DEFAULT_BUS_NAME
from endon_core.findings import Severity


class ResponseMode(StrEnum):
    DRY_RUN = "dry_run"
    ENFORCE = "enforce"


@dataclass(frozen=True)
class Settings:
    region: str = "us-east-1"
    event_bus_name: str = DEFAULT_BUS_NAME
    incidents_table: str = "endon-incidents"
    findings_table: str = "endon-findings"
    alerts_topic_arn: str | None = None
    evidence_bucket: str | None = None
    response_mode: ResponseMode = ResponseMode.DRY_RUN
    protected_tag_key: str = "endon:protected"
    notify_min_severity: Severity = Severity.MEDIUM

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> Settings:
        env = os.environ if env is None else env
        # Anything other than an explicit "enforce" runs in dry-run: automated
        # containment must be switched on deliberately, never by a typo.
        mode = env.get("ENDON_RESPONSE_MODE", "").strip().lower()
        return cls(
            region=env.get("ENDON_REGION")
            or env.get("AWS_REGION")
            or env.get("AWS_DEFAULT_REGION")
            or "us-east-1",
            event_bus_name=env.get("ENDON_EVENT_BUS", DEFAULT_BUS_NAME),
            incidents_table=env.get("ENDON_INCIDENTS_TABLE", "endon-incidents"),
            findings_table=env.get("ENDON_FINDINGS_TABLE", "endon-findings"),
            alerts_topic_arn=env.get("ENDON_ALERTS_TOPIC_ARN") or None,
            evidence_bucket=env.get("ENDON_EVIDENCE_BUCKET") or None,
            response_mode=ResponseMode.ENFORCE if mode == "enforce" else ResponseMode.DRY_RUN,
            protected_tag_key=env.get("ENDON_PROTECTED_TAG", "endon:protected"),
            notify_min_severity=Severity(env.get("ENDON_NOTIFY_MIN_SEVERITY", "MEDIUM").upper()),
        )
