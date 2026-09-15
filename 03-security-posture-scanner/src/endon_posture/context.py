"""Scan context: shared clients, identity and the finding builder used by every check."""

from __future__ import annotations

from dataclasses import dataclass

from endon_core.aws import ClientFactory
from endon_core.events import Source
from endon_core.findings import Finding, Resource
from endon_posture.controls import CONTROLS, Control


@dataclass
class ScanContext:
    clients: ClientFactory
    account_id: str
    region: str
    partition: str = "aws"

    def account_resource(self) -> Resource:
        return Resource("AwsAccount", f"AWS::::Account:{self.account_id}", region=self.region)

    def finding(
        self,
        control_id: str,
        resource: Resource,
        *,
        detail: str = "",
        tags: dict[str, str] | None = None,
    ) -> Finding:
        control: Control = CONTROLS[control_id]
        title = (
            control.title if resource.type == "AwsAccount" else f"{control.title}: {resource.name}"
        )
        description = f"{control.rationale} {detail}".strip()
        return Finding(
            source=Source.POSTURE_SCANNER,
            type=control.finding_type,
            title=title,
            severity=control.severity,
            account_id=self.account_id,
            region=self.region,
            resources=[resource],
            description=description,
            remediation=control.remediation,
            control_id=control.id,
            domain=control.domain,
            tags={"service": control.service, **(tags or {})},
        )
