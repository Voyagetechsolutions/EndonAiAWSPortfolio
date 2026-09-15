"""Shared contracts for the Endon AI cloud security platform.

Every Endon component speaks the same language: producers emit a ``Finding``,
the response engine turns findings into ``Incident`` records, and components
talk to each other through events on the Endon security bus.
"""

from endon_core.findings import Domain, Finding, Resource, Severity
from endon_core.incidents import (
    ActionKind,
    ActionRecord,
    ActionStatus,
    Incident,
    IncidentStatus,
    TimelineEntry,
)

__version__ = "0.1.0"

__all__ = [
    "ActionKind",
    "ActionRecord",
    "ActionStatus",
    "Domain",
    "Finding",
    "Incident",
    "IncidentStatus",
    "Resource",
    "Severity",
    "TimelineEntry",
]
