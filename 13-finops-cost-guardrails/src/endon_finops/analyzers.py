"""The analyzers: each turns cost rows into zero or more hits for a control."""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Callable
from dataclasses import dataclass

from endon_finops.costs import CostRow, daily_series, detect_spike

# The cost-allocation tag every resource should carry.
TAG_KEY = "team"
# Usage types that are pure waste (an Elastic IP is only billed while idle).
_IDLE_USAGE = ("ElasticIP:IdleAddress",)
# Below these dollar amounts, a signal is noise.
_UNTAGGED_FLOOR = 50.0
_IDLE_FLOOR = 5.0


@dataclass(frozen=True)
class Hit:
    control_id: str
    resource: str
    detail: str


def _ec2(row: CostRow) -> bool:
    return row.service.startswith(("Amazon Elastic Compute Cloud", "Amazon EC2", "EC2"))


def _egress(row: CostRow) -> bool:
    return "DataTransfer-Out" in row.usage_type or "Out-Bytes" in row.usage_type


# ---- FinOps -----------------------------------------------------------------------
def untagged_spend(rows: list[CostRow]) -> list[Hit]:
    total = round(sum(r.amount for r in rows if TAG_KEY not in r.tags), 2)
    if total >= _UNTAGGED_FLOOR:
        return [
            Hit("FIN-001", "account", f"${total} of spend has no '{TAG_KEY}' tag over the period")
        ]
    return []


def idle_resources(rows: list[CostRow]) -> list[Hit]:
    by_type: dict[str, float] = defaultdict(float)
    for row in rows:
        if any(marker in row.usage_type for marker in _IDLE_USAGE):
            by_type[row.usage_type] += row.amount
    return [
        Hit("FIN-002", usage, f"${round(amount, 2)} paid for idle {usage}")
        for usage, amount in by_type.items()
        if amount >= _IDLE_FLOOR
    ]


def cost_anomaly(rows: list[CostRow]) -> list[Hit]:
    spike = detect_spike(daily_series(rows, lambda r: True), factor=2.0, floor=100.0)
    if spike:
        return [
            Hit(
                "FIN-003", "total", f"${spike.amount} on {spike.date} vs ${spike.baseline} baseline"
            )
        ]
    return []


# ---- Security-cost ----------------------------------------------------------------
def compute_spike(rows: list[CostRow]) -> list[Hit]:
    spike = detect_spike(daily_series(rows, _ec2), factor=3.0, floor=50.0)
    if spike:
        return [
            Hit(
                "FIN-101",
                "EC2",
                f"compute ${spike.amount} on {spike.date} ({spike.multiple:.0f}x baseline)",
            )
        ]
    return []


def egress_spike(rows: list[CostRow]) -> list[Hit]:
    spike = detect_spike(daily_series(rows, _egress), factor=3.0, floor=20.0)
    if spike:
        return [
            Hit(
                "FIN-102",
                "DataTransfer-Out",
                f"egress ${spike.amount} on {spike.date} ({spike.multiple:.0f}x baseline)",
            )
        ]
    return []


def new_region_spend(rows: list[CostRow]) -> list[Hit]:
    if not rows:
        return []
    latest = max(r.date for r in rows)
    dates_by_region: dict[str, set[str]] = defaultdict(set)
    latest_amount: dict[str, float] = defaultdict(float)
    for row in rows:
        if not row.region:
            continue
        dates_by_region[row.region].add(row.date)
        if row.date == latest:
            latest_amount[row.region] += row.amount
    hits = []
    for region, dates in dates_by_region.items():
        # Cost on the latest day only — the region had no spend before.
        if dates == {latest} and latest_amount[region] >= 20.0:
            hits.append(
                Hit(
                    "FIN-103",
                    region,
                    f"${round(latest_amount[region], 2)} first appeared in {region} on {latest}",
                )
            )
    return hits


ANALYZERS: tuple[Callable[[list[CostRow]], list[Hit]], ...] = (
    untagged_spend,
    idle_resources,
    cost_anomaly,
    compute_spike,
    egress_spike,
    new_region_spend,
)
