"""Load and aggregate cost data — a simplified Cost & Usage Report / Cost Explorer export.

The input is daily cost line items: a date, the service, the usage type, a region, an amount,
and the resource's cost-allocation tags. This is what ``aws ce get-cost-and-usage`` or a CUR
export gives you (flattened). The analyzers build per-key daily time series from these rows and
look for waste and for spikes — a cost spike is often the *first* sign of a compromise, before a
detector fires.
"""

from __future__ import annotations

import json
from collections import defaultdict
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from statistics import median
from typing import Any


@dataclass(frozen=True)
class CostRow:
    date: str
    service: str
    usage_type: str
    region: str
    amount: float
    tags: dict[str, str] = field(default_factory=dict)


def load(rows: list[dict[str, Any]]) -> list[CostRow]:
    parsed: list[CostRow] = []
    for row in rows:
        parsed.append(
            CostRow(
                date=row.get("date", ""),
                service=row.get("service", ""),
                usage_type=row.get("usage_type", ""),
                region=row.get("region", ""),
                amount=float(row.get("amount", 0.0)),
                tags=row.get("tags") or {},
            )
        )
    return parsed


def load_file(path: str | Path) -> list[CostRow]:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    rows = data.get("rows", data) if isinstance(data, dict) else data
    return load(rows)


def daily_series(rows: list[CostRow], match: Callable[[CostRow], bool]) -> list[tuple[str, float]]:
    """Total the matching rows per day, returned oldest-first as (date, amount)."""
    totals: dict[str, float] = defaultdict(float)
    for row in rows:
        if match(row):
            totals[row.date] += row.amount
    return sorted(totals.items())


@dataclass(frozen=True)
class Spike:
    date: str
    amount: float
    baseline: float

    @property
    def multiple(self) -> float:
        return self.amount / self.baseline if self.baseline else float("inf")


def detect_spike(
    series: list[tuple[str, float]], factor: float = 3.0, floor: float = 20.0
) -> Spike | None:
    """Flag the last day if it dwarfs the baseline of the prior days.

    A spike needs the latest day to be both material (>= ``floor``) and well above the median of
    the earlier days (> ``factor`` x). A brand-new cost (no baseline) above the floor also counts.
    """
    if len(series) < 3:
        return None
    *baseline, (last_date, last_amount) = series
    base_median = median(a for _, a in baseline) if baseline else 0.0
    if last_amount < floor:
        return None
    if last_amount > max(base_median * factor, floor):
        return Spike(last_date, round(last_amount, 2), round(base_median, 2))
    return None
