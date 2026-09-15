"""Spreadsheet-friendly posture report: one row per finding."""

from __future__ import annotations

import csv
import io

from endon_posture.scanner import ScanResult

_COLUMNS = ["severity", "control", "service", "type", "resource", "title", "remediation"]


def render_csv(result: ScanResult) -> str:
    buffer = io.StringIO()
    writer = csv.writer(buffer, lineterminator="\n")
    writer.writerow(_COLUMNS)
    for finding in result.by_severity():
        writer.writerow(
            [
                finding.severity.value,
                finding.control_id or "",
                finding.tags.get("service", ""),
                finding.type,
                "; ".join(r.id for r in finding.resources),
                finding.title,
                finding.remediation,
            ]
        )
    return buffer.getvalue()
