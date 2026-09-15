"""Scan context: shared clients, identity, the secret scanner, and the finding builder."""

from __future__ import annotations

from dataclasses import dataclass, field

from endon_core.aws import ClientFactory
from endon_core.events import Source
from endon_core.findings import Domain, Finding, Resource, Severity
from endon_dataprotection.secrets import SecretScanner


@dataclass
class ScanContext:
    clients: ClientFactory
    account_id: str
    region: str
    partition: str = "aws"
    secrets: SecretScanner = field(default_factory=SecretScanner)

    def finding(
        self,
        *,
        finding_type: str,
        title: str,
        severity: Severity,
        resource: Resource,
        description: str,
        remediation: str,
        control_id: str,
        tags: dict[str, str] | None = None,
    ) -> Finding:
        return Finding(
            source=Source.DATA_PROTECTION,
            type=finding_type,
            title=title,
            severity=severity,
            account_id=self.account_id,
            region=self.region,
            resources=[resource],
            description=description,
            remediation=remediation,
            control_id=control_id,
            domain=Domain.DATA_PROTECTION,
            tags=tags or {},
        )
