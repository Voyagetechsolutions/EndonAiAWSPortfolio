"""Event contracts and publishers for the Endon security bus.

Components never call each other directly. They publish events to a custom
EventBridge bus and subscribe with rules. Each project stays independently
deployable, and the platform still behaves as one system.
"""

from __future__ import annotations

import json
import uuid
from collections import deque
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from typing import Any, Protocol

from endon_core.timeutil import isoformat, utc_now

DEFAULT_BUS_NAME = "endon-security-bus"


class Source:
    DETECTION = "endon.detection"
    IAM_ANALYZER = "endon.iam-analyzer"
    POSTURE_SCANNER = "endon.posture-scanner"
    FORENSICS = "endon.forensics"
    DATA_PROTECTION = "endon.data-protection"
    SOC = "endon.soc"


# The only Endon components whose findings the response engine subscribes to.
FINDING_PRODUCERS = (Source.IAM_ANALYZER, Source.POSTURE_SCANNER, Source.DATA_PROTECTION)


class DetailType:
    FINDING = "Endon Finding"
    INCIDENT_UPDATED = "Endon Incident Updated"
    FORENSICS_REQUESTED = "Endon Forensics Requested"
    FORENSICS_COMPLETED = "Endon Forensics Completed"


class EventPublishError(RuntimeError):
    pass


class EventPublisher(Protocol):
    def publish(
        self,
        source: str,
        detail_type: str,
        detail: Mapping[str, Any],
        resources: Iterable[str] = (),
    ) -> None: ...


class EventBridgePublisher:
    def __init__(self, bus_name: str, client: Any) -> None:
        self.bus_name = bus_name
        self._client = client

    def publish(
        self,
        source: str,
        detail_type: str,
        detail: Mapping[str, Any],
        resources: Iterable[str] = (),
    ) -> None:
        entry = {
            "EventBusName": self.bus_name,
            "Source": source,
            "DetailType": detail_type,
            "Detail": json.dumps(detail, default=str),
            "Resources": [r for r in resources if r.startswith("arn:")],
        }
        response = self._client.put_events(Entries=[entry])
        if response.get("FailedEntryCount"):
            raise EventPublishError(json.dumps(response.get("Entries", [])))


@dataclass
class Subscription:
    name: str
    pattern: Mapping[str, Any]
    target: Callable[[dict[str, Any]], Any]


class InMemoryEventBus:
    """Local stand-in for EventBridge, used by tests and the offline demo.

    Events use the real EventBridge envelope and rules use EventBridge pattern
    syntax, so the patterns deployed to AWS are the ones exercised locally.
    Delivery is queued: a target that publishes new events does not recurse.
    Target failures are captured in ``errors``, the local equivalent of a DLQ.
    """

    def __init__(self, account_id: str = "000000000000", region: str = "us-east-1") -> None:
        self.account_id = account_id
        self.region = region
        self.history: list[dict[str, Any]] = []
        self.subscriptions: list[Subscription] = []
        self.errors: list[tuple[str, dict[str, Any], Exception]] = []
        self._queue: deque[dict[str, Any]] = deque()
        self._dispatching = False

    def subscribe(
        self, name: str, pattern: Mapping[str, Any], target: Callable[[dict[str, Any]], Any]
    ) -> None:
        self.subscriptions.append(Subscription(name, pattern, target))

    def publish(
        self,
        source: str,
        detail_type: str,
        detail: Mapping[str, Any],
        resources: Iterable[str] = (),
    ) -> None:
        self.put_event(
            {
                "version": "0",
                "id": str(uuid.uuid4()),
                "detail-type": detail_type,
                "source": source,
                "account": self.account_id,
                "time": isoformat(utc_now(), "seconds"),
                "region": self.region,
                "resources": list(resources),
                "detail": json.loads(json.dumps(detail, default=str)),
            }
        )

    def put_event(self, event: dict[str, Any]) -> None:
        self.history.append(event)
        self._queue.append(event)
        if self._dispatching:
            return
        self._dispatching = True
        try:
            while self._queue:
                current = self._queue.popleft()
                for subscription in self.subscriptions:
                    if not matches_pattern(subscription.pattern, current):
                        continue
                    try:
                        subscription.target(current)
                    except Exception as exc:  # mirror async delivery: record, keep going
                        self.errors.append((subscription.name, current, exc))
        finally:
            self._dispatching = False

    def events(self, detail_type: str | None = None) -> list[dict[str, Any]]:
        return [e for e in self.history if detail_type is None or e["detail-type"] == detail_type]


def matches_pattern(pattern: Mapping[str, Any], event: Any) -> bool:
    """Evaluate an EventBridge event pattern.

    Supports exact values, ``prefix``, ``anything-but``, ``numeric`` and ``exists``
    matchers, nested objects, and arrays of objects (matched if any element matches).
    """
    if isinstance(event, list):
        return any(matches_pattern(pattern, item) for item in event)
    if not isinstance(event, Mapping):
        return False
    for key, expected in pattern.items():
        present = key in event
        value = event.get(key)
        if isinstance(expected, Mapping):
            if not present or not matches_pattern(expected, value):
                return False
        elif not _matches_any(expected, present, value):
            return False
    return True


def _matches_any(matchers: list[Any], present: bool, value: Any) -> bool:
    candidates = value if isinstance(value, list) else [value]
    for matcher in matchers:
        if isinstance(matcher, Mapping) and "exists" in matcher:
            if bool(matcher["exists"]) == present:
                return True
            continue
        if present and any(_matches_one(matcher, candidate) for candidate in candidates):
            return True
    return False


def _matches_one(matcher: Any, candidate: Any) -> bool:
    if not isinstance(matcher, Mapping):
        return matcher == candidate
    if "prefix" in matcher:
        return isinstance(candidate, str) and candidate.startswith(matcher["prefix"])
    if "anything-but" in matcher:
        excluded = matcher["anything-but"]
        excluded = excluded if isinstance(excluded, list) else [excluded]
        return candidate not in excluded
    if "numeric" in matcher:
        if isinstance(candidate, bool) or not isinstance(candidate, int | float):
            return False
        return _numeric(matcher["numeric"], candidate)
    raise ValueError(f"Unsupported event pattern matcher: {dict(matcher)}")


_OPERATORS: dict[str, Callable[[float, float], bool]] = {
    "=": lambda a, b: a == b,
    "<": lambda a, b: a < b,
    "<=": lambda a, b: a <= b,
    ">": lambda a, b: a > b,
    ">=": lambda a, b: a >= b,
}


def _numeric(conditions: list[Any], candidate: float) -> bool:
    pairs = zip(conditions[::2], conditions[1::2], strict=True)
    return all(_OPERATORS[op](candidate, bound) for op, bound in pairs)
