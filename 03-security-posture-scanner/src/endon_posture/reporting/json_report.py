"""Machine-readable posture report."""

from __future__ import annotations

import json

from endon_posture.scanner import ScanResult


def render_json(result: ScanResult) -> str:
    return json.dumps(result.to_dict(), indent=2, default=str)
