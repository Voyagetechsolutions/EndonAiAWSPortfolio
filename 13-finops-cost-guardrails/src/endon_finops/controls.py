"""The FinOps + security-cost control catalog.

Two families. **FinOps** controls catch waste and drift — untagged spend, idle resources, a
budget-busting day. **Security-cost** controls treat a cost spike as a security signal: a
sudden surge in compute is what cryptomining looks like on the bill; a surge in data-transfer-
out is what exfiltration looks like; spend in a region you never use is where an attacker spins
up miners. The bill is a detector too, and often the first one to move.
"""

from __future__ import annotations

from dataclasses import dataclass

from endon_core.findings import Domain, Severity


@dataclass(frozen=True)
class Control:
    id: str
    area: str
    title: str
    severity: Severity
    finding_type: str
    domain: Domain
    remediation: str


def _c(cid, area, name, title, severity, domain, remediation) -> Control:
    return Control(cid, area, title, severity, f"FinOps:{area}/{name}", domain, remediation)


_ALL = [
    # --- FinOps (waste & governance) ------------------------------------------------
    _c(
        "FIN-001",
        "Waste",
        "UntaggedSpend",
        "Significant untagged spend",
        Severity.MEDIUM,
        Domain.GOVERNANCE,
        "Enforce a cost-allocation tag (e.g. team) so every dollar has an owner.",
    ),
    _c(
        "FIN-002",
        "Waste",
        "IdleResource",
        "Paying for idle resources",
        Severity.LOW,
        Domain.GOVERNANCE,
        "Release idle Elastic IPs and clean up unattached resources.",
    ),
    _c(
        "FIN-003",
        "Waste",
        "CostAnomaly",
        "Daily cost anomaly (budget)",
        Severity.MEDIUM,
        Domain.GOVERNANCE,
        "Investigate the cost spike; confirm it is expected before it recurs.",
    ),
    # --- Security-cost (a cost spike as a compromise signal) ------------------------
    _c(
        "FIN-101",
        "Security",
        "ComputeSpike",
        "Compute cost spike (possible cryptomining)",
        Severity.HIGH,
        Domain.INCIDENT_RESPONSE,
        "Investigate the account for unauthorized instances (cryptomining); correlate with GuardDuty.",
    ),
    _c(
        "FIN-102",
        "Security",
        "EgressSpike",
        "Data-transfer-out spike (possible exfiltration)",
        Severity.HIGH,
        Domain.DATA_PROTECTION,
        "Investigate the source of the egress; a surge in transfer-out can be data exfiltration.",
    ),
    _c(
        "FIN-103",
        "Security",
        "NewRegionSpend",
        "Spend appeared in an unused region",
        Severity.MEDIUM,
        Domain.INCIDENT_RESPONSE,
        "Confirm the region is expected; attackers launch resources in regions you do not use.",
    ),
]

BY_ID: dict[str, Control] = {c.id: c for c in _ALL}


def all_controls() -> list[Control]:
    return list(_ALL)


def get(control_id: str) -> Control:
    return BY_ID[control_id]
