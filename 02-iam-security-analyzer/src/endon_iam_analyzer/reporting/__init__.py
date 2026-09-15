"""Report renderers for an ``AnalysisResult``."""

from endon_iam_analyzer.reporting.console import render_console
from endon_iam_analyzer.reporting.csv_report import render_csv
from endon_iam_analyzer.reporting.html_report import render_html
from endon_iam_analyzer.reporting.json_report import render_json

RENDERERS = {
    "console": render_console,
    "json": render_json,
    "csv": render_csv,
    "html": render_html,
}

__all__ = ["RENDERERS", "render_console", "render_csv", "render_html", "render_json"]
