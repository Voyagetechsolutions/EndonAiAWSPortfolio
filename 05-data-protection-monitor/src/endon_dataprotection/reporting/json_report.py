"""Machine-readable data-protection report (all secret values already redacted)."""

from __future__ import annotations

import json

from endon_dataprotection.scanner import ScanResult


def render_json(result: ScanResult) -> str:
    return json.dumps(result.to_dict(), indent=2, default=str)
