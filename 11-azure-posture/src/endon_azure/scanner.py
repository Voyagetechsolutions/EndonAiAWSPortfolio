"""Scan Azure resources into Endon findings — the AWS posture scanner's Azure sibling."""

from __future__ import annotations

from endon_azure.checks import CHECKS
from endon_azure.controls import Control, get
from endon_azure.resources import AzureResource, load, load_file
from endon_core.findings import Finding, Resource

SOURCE = "endon.azure"


def scan(resources: list[AzureResource]) -> list[Finding]:
    findings: list[Finding] = []
    for resource in resources:
        for check in CHECKS.get(resource.type, ()):  # only checks for this resource type
            if check.predicate(resource):
                findings.append(_finding(get(check.control_id), resource))
    findings.sort(
        key=lambda f: (-f.severity.rank, f.type, f.resources[0].id if f.resources else "")
    )
    return findings


def scan_rows(rows: list[dict]) -> list[Finding]:
    return scan(load(rows))


def scan_file(path) -> list[Finding]:
    return scan(load_file(path))


def _finding(control: Control, resource: AzureResource) -> Finding:
    return Finding(
        source=SOURCE,
        type=control.finding_type,
        title=control.title,
        severity=control.severity,
        account_id=resource.resource_group or "azure",
        region=resource.location or "global",
        domain=control.domain,
        resources=[
            Resource(
                type="AzureResource", id=resource.id or resource.name, region=resource.location
            )
        ],
        description=f"{control.title} ({resource.name}).",
        remediation=control.remediation,
        control_id=control.id,
        tags={"cloud": "azure"},
    )
