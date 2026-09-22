"""Normalize CloudTrail records into the event shape the detections reason over.

CloudTrail is the audit log of every API call in an account. A record has an ``eventName``, an
``eventSource``, who made the call (``userIdentity``), from where (``sourceIPAddress``), when,
and whether it failed (``errorCode``). This flattens all of that into one ``Event`` so a
detection never has to dig through CloudTrail's nested shape — and it parses the timestamp, so
the correlation rules can slide a time window over a principal's activity.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class Event:
    time: datetime
    name: str
    source: str
    region: str
    source_ip: str
    error_code: str | None
    identity_type: str
    principal: str
    account_id: str
    request_parameters: dict[str, Any] = field(default_factory=dict)
    raw: dict[str, Any] = field(default_factory=dict, repr=False)

    @property
    def failed(self) -> bool:
        return bool(self.error_code)


def _principal(identity: dict[str, Any]) -> str:
    """A stable name for who acted: the ARN, else user/role name, else the account (root)."""
    if identity.get("type") == "Root":
        return "root:" + identity.get("accountId", "")
    issuer = identity.get("sessionContext", {}).get("sessionIssuer", {}).get("userName")
    return (
        identity.get("arn")
        or identity.get("userName")
        or issuer
        or identity.get("accountId", "unknown")
    )


def from_record(record: dict[str, Any]) -> Event:
    identity = record.get("userIdentity") or {}
    return Event(
        time=_parse_time(record.get("eventTime", "")),
        name=record.get("eventName", ""),
        source=record.get("eventSource", ""),
        region=record.get("awsRegion", ""),
        source_ip=record.get("sourceIPAddress", ""),
        error_code=record.get("errorCode"),
        identity_type=identity.get("type", ""),
        principal=_principal(identity),
        account_id=record.get("recipientAccountId") or identity.get("accountId", ""),
        request_parameters=record.get("requestParameters") or {},
        raw=record,
    )


def load(records: list[dict[str, Any]]) -> list[Event]:
    events = [from_record(r) for r in records]
    events.sort(key=lambda e: e.time)
    return events


def load_file(path: str | Path) -> list[Event]:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    records = data.get("Records", data) if isinstance(data, dict) else data
    return load(records)


def _parse_time(value: str) -> datetime:
    if not value:
        return datetime.now(UTC)
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)
