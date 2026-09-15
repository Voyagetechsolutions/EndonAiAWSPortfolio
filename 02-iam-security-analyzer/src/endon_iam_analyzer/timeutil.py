"""Small time helper for credential ages (the credential report uses varied formats)."""

from __future__ import annotations

from datetime import datetime

from endon_core.timeutil import parse_timestamp

_UNKNOWN = {"", "N/A", "no_information", "not_supported", "none"}


def age_in_days(timestamp: str | None, now: datetime) -> int | None:
    """Whole days between ``timestamp`` and ``now``; None if the value is unknown."""
    if timestamp is None or str(timestamp).strip().lower() in {v.lower() for v in _UNKNOWN}:
        return None
    try:
        moment = parse_timestamp(str(timestamp))
    except ValueError:
        return None
    return max(0, (now - moment).days)
