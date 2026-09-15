"""Report renderers for a data-protection ``ScanResult``."""

from endon_dataprotection.reporting.console import render_console
from endon_dataprotection.reporting.html_report import render_html
from endon_dataprotection.reporting.json_report import render_json

RENDERERS = {"console": render_console, "json": render_json, "html": render_html}

__all__ = ["RENDERERS", "render_console", "render_html", "render_json"]
