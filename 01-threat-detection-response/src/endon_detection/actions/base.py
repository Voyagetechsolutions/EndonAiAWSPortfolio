"""Base class for response actions."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, ClassVar

from endon_core.aws import ClientFactory
from endon_core.config import Settings
from endon_core.events import EventPublisher
from endon_core.findings import Finding, Resource
from endon_core.incidents import ActionKind, Incident


class ActionSkipped(Exception):
    """Raised when an action finds at runtime that there is nothing to do."""


@dataclass
class ActionContext:
    finding: Finding
    incident: Incident
    clients: ClientFactory
    settings: Settings
    publisher: EventPublisher


@dataclass
class ActionOutcome:
    message: str
    data: dict[str, Any] = field(default_factory=dict)


class Action(ABC):
    name: ClassVar[str]
    kind: ClassVar[ActionKind]
    resource_types: ClassVar[tuple[str, ...]] = ()

    def targets(self, ctx: ActionContext) -> list[Resource]:
        return [r for r in ctx.finding.resources if r.type in self.resource_types]

    def not_applicable(self, ctx: ActionContext) -> str:
        return f"Finding has no {' or '.join(self.resource_types)} resource"

    @abstractmethod
    def plan(self, target: Resource, ctx: ActionContext) -> str:
        """What ``execute`` would do, phrased to follow 'Would ...' in dry-run records."""

    @abstractmethod
    def execute(self, target: Resource, ctx: ActionContext) -> ActionOutcome: ...
