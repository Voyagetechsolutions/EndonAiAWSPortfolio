"""Machine-readable report: the analysis result as JSON."""

from __future__ import annotations

import json

from endon_iam_analyzer.analyzer import AnalysisResult


def render_json(result: AnalysisResult) -> str:
    return json.dumps(result.to_dict(), indent=2, default=str)
