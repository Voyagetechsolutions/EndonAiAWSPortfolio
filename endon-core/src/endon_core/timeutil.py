"""UTC time helpers. All Endon timestamps are ISO 8601 in UTC with a ``Z`` suffix."""

from __future__ import annotations

from datetime import UTC, datetime


def utc_now() -> datetime:
    return datetime.now(UTC)


def isoformat(value: datetime, timespec: str = "milliseconds") -> str:
    return value.astimezone(UTC).isoformat(timespec=timespec).replace("+00:00", "Z")


def parse_timestamp(value: str) -> datetime:
    parsed = datetime.fromisoformat(value)
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


def seconds_between(start: str, end: str) -> float:
    return (parse_timestamp(end) - parse_timestamp(start)).total_seconds()
