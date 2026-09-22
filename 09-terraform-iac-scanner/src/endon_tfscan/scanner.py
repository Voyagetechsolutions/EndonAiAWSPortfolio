"""Run the rules over a plan and emit Endon findings.

The output is ``endon_core.Finding`` objects — the same type the posture scanner and IAM
analyzer produce — so a Terraform finding flows through the platform's bus, stores, reports
and SOC with no special-casing. The scanner shifts detection left: the same class of issue
the posture scanner (Project 3) finds in a running account, this catches in the plan, before
anything is created.
"""

from __future__ import annotations

from endon_core.findings import Finding, Resource
from endon_tfscan.controls import Control, get
from endon_tfscan.plan import Plan
from endon_tfscan.rules import RULES

SOURCE = "endon.tfscan"


def scan(plan: Plan, account_id: str = "terraform", region: str = "global") -> list[Finding]:
    """Evaluate every rule against the plan and return one finding per violation."""
    findings: list[Finding] = []
    for rule in RULES:
        control = get(rule.control_id)
        for resource in plan.of_type(*rule.resource_types):
            if rule.predicate(resource):
                findings.append(_finding(control, resource.address, account_id, region))
    findings.sort(
        key=lambda f: (-f.severity.rank, f.type, f.resources[0].id if f.resources else "")
    )
    return findings


def _finding(control: Control, address: str, account_id: str, region: str) -> Finding:
    return Finding(
        source=SOURCE,
        type=control.finding_type,
        title=control.title,
        severity=control.severity,
        account_id=account_id,
        region=region,
        domain=control.domain,
        resources=[Resource(type="TerraformResource", id=address, region=region)],
        description=f"{control.title} ({address}) — flagged in the Terraform plan before apply.",
        remediation=control.remediation,
        control_id=control.id,
        tags={"iac": "terraform"},
    )
