"""Collector base class and the context passed to each one."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import ClassVar

from endon_core.aws import ClientFactory
from endon_forensics.evidence_store import EvidenceStore
from endon_forensics.models import EvidenceItem, ForensicCase

COLLECTORS: list[Collector] = []


@dataclass
class CollectorContext:
    case: ForensicCase
    clients: ClientFactory
    store: EvidenceStore


class Collector(ABC):
    id: ClassVar[str]
    kind: ClassVar[str]
    order: ClassVar[int]  # lower runs first (more volatile)
    critical: ClassVar[bool] = False  # a failed critical collector downgrades the case

    @abstractmethod
    def collect(self, ctx: CollectorContext) -> list[EvidenceItem]:
        """Collect one or more evidence items. Raising is caught by the engine and recorded."""
