"""Evidence collectors, ordered by volatility (most volatile first).

Volatile in-memory state (processes, connections) is captured before stable API metadata,
which is captured before disk snapshots — the classic forensic order of volatility, so the
most perishable evidence is secured first.
"""

from endon_forensics.collectors.base import COLLECTORS, Collector, CollectorContext
from endon_forensics.collectors.cloudtrail import CloudTrailCollector
from endon_forensics.collectors.console import ConsoleCollector
from endon_forensics.collectors.metadata import MetadataCollector
from endon_forensics.collectors.snapshots import DiskSnapshotCollector
from endon_forensics.collectors.volatile import VolatileDataCollector

# Registered in order of volatility.
DEFAULT_COLLECTORS: list[Collector] = sorted(
    [
        VolatileDataCollector(),
        MetadataCollector(),
        ConsoleCollector(),
        CloudTrailCollector(),
        DiskSnapshotCollector(),
    ],
    key=lambda c: c.order,
)

__all__ = [
    "COLLECTORS",
    "DEFAULT_COLLECTORS",
    "Collector",
    "CollectorContext",
    "CloudTrailCollector",
    "ConsoleCollector",
    "DiskSnapshotCollector",
    "MetadataCollector",
    "VolatileDataCollector",
]
