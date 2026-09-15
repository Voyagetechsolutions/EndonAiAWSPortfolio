"""Secrets Manager posture: secrets without automatic rotation."""

from __future__ import annotations

from collections.abc import Iterator

from endon_core.findings import Finding, Resource, Severity
from endon_dataprotection.context import ScanContext
from endon_dataprotection.scanners.base import scanner


@scanner("SecretsManager")
def rotation_disabled(ctx: ScanContext) -> Iterator[Finding]:
    client = ctx.clients("secretsmanager")
    for page in client.get_paginator("list_secrets").paginate():
        for secret in page.get("SecretList", []):
            if secret.get("RotationEnabled"):
                continue
            name = secret.get("Name", secret.get("ARN", ""))
            resource = Resource(
                "AwsSecretsManagerSecret",
                secret.get("ARN", name),
                region=ctx.region,
                details={"name": name},
            )
            yield ctx.finding(
                finding_type="DataProtection:SecretsManager/RotationDisabled",
                title=f"Secrets Manager secret has rotation disabled: {name}",
                severity=Severity.MEDIUM,
                resource=resource,
                description=(
                    f"Secret '{name}' does not have automatic rotation enabled, so a compromised "
                    "value stays valid indefinitely."
                ),
                remediation="Enable automatic rotation with a rotation Lambda and a suitable schedule.",
                control_id="DP-SM-001",
                tags={"service": "SecretsManager"},
            )
