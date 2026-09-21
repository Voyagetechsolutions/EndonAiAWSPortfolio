"""Jinja2 environment for the server-rendered SOC pages.

Autoescaping is on for every template: finding titles, resource ids and descriptions come from
scanned AWS data and must never be able to inject markup into the console. Server-side
rendering keeps the browser doing nothing but displaying HTML — no client-side data handling,
no API token in the page — which is the right default for a security tool.
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

TEMPLATES_DIR = Path(__file__).resolve().parent / "templates"

_SEVERITY_CLASS = {
    "CRITICAL": "sev-crit",
    "HIGH": "sev-high",
    "MEDIUM": "sev-med",
    "LOW": "sev-low",
    "INFORMATIONAL": "sev-info",
}
_STATUS_CLASS = {
    "CONTAINED": "ok",
    "MONITORING": "warn",
    "PARTIALLY_CONTAINED": "warn",
    "SUPPRESSED": "warn",
    "OPEN": "bad",
    "FAILED": "bad",
    "DRY_RUN": "muted",
}


@lru_cache(maxsize=1)
def environment() -> Environment:
    env = Environment(
        loader=FileSystemLoader(str(TEMPLATES_DIR)),
        autoescape=select_autoescape(["html"]),
        trim_blocks=True,
        lstrip_blocks=True,
    )
    env.filters["severity_class"] = lambda s: _SEVERITY_CLASS.get(str(s).upper(), "sev-info")
    env.filters["status_class"] = lambda s: _STATUS_CLASS.get(str(s).upper(), "muted")
    env.filters["short_time"] = _short_time
    return env


def render(template: str, **context: object) -> str:
    return environment().get_template(template).render(**context)


def _short_time(value: str | None) -> str:
    """`2026-09-21T09:42:10.000Z` -> `09:42` for the compact incident list."""
    if not value or "T" not in value:
        return value or ""
    clock = value.split("T", 1)[1]
    return clock[:5]
