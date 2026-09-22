"""Run the analyzers over cost rows and emit Endon findings.

The output is ``endon_core.Finding`` objects, so a cost anomaly lands in the same SOC and ASFF as
a GuardDuty finding — which is the point: a compute or egress spike is a security signal, and it
belongs next to the detections it corroborates (Project 12) or precedes.
"""

from __future__ import annotations

from endon_core.findings import Finding, Resource
from endon_finops.analyzers import ANALYZERS, Hit
from endon_finops.controls import Control, get
from endon_finops.costs import CostRow, load, load_file

SOURCE = "endon.finops"


def analyze(rows: list[CostRow]) -> list[Finding]:
    findings = [_finding(hit) for analyzer in ANALYZERS for hit in analyzer(rows)]
    findings.sort(key=lambda f: (-f.severity.rank, f.type))
    return findings


def analyze_rows(rows: list[dict]) -> list[Finding]:
    return analyze(load(rows))


def analyze_file(path) -> list[Finding]:
    return analyze(load_file(path))


def _finding(hit: Hit) -> Finding:
    control: Control = get(hit.control_id)
    return Finding(
        source=SOURCE,
        type=control.finding_type,
        title=control.title,
        severity=control.severity,
        account_id="cost-explorer",
        region="global",
        domain=control.domain,
        resources=[Resource(type="CostDimension", id=hit.resource, region="global")],
        description=f"{control.title} — {hit.detail}.",
        remediation=control.remediation,
        control_id=control.id,
        tags={"discipline": "finops"},
    )
