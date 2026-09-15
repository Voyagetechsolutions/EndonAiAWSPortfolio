"""Spreadsheet-friendly report: one row per finding."""

from __future__ import annotations

import csv
import io

from endon_iam_analyzer.analyzer import AnalysisResult

_COLUMNS = ["severity", "type", "control_id", "title", "resources", "remediation"]


def render_csv(result: AnalysisResult) -> str:
    buffer = io.StringIO()
    writer = csv.writer(buffer, lineterminator="\n")
    writer.writerow(_COLUMNS)
    for finding in result.by_severity():
        writer.writerow(
            [
                finding.severity.value,
                finding.type,
                finding.control_id or "",
                finding.title,
                "; ".join(r.id for r in finding.resources),
                finding.remediation,
            ]
        )
    return buffer.getvalue()
