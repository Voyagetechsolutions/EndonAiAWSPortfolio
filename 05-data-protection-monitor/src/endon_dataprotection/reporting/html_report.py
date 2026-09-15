"""Self-contained HTML data-protection report (redacted)."""

from __future__ import annotations

import html

from endon_core.findings import Severity
from endon_dataprotection.scanner import ScanResult

_SEVERITY_COLORS = {
    "CRITICAL": "#b3123b",
    "HIGH": "#d1531f",
    "MEDIUM": "#b8860b",
    "LOW": "#2a7d5f",
    "INFORMATIONAL": "#4a5568",
}


def _score_color(score: int) -> str:
    return "#2a7d5f" if score >= 80 else "#b8860b" if score >= 50 else "#b3123b"


def render_html(result: ScanResult) -> str:
    counts = result.counts
    cards = "".join(
        f'<div class="card"><div class="num" style="color:{_SEVERITY_COLORS[s.value]}">{counts[s.value]}</div>'
        f'<div class="lbl">{s.value.title()}</div></div>'
        for s in reversed(list(Severity))
    )
    rows = "\n".join(_row(f) for f in result.by_severity())
    empty = "" if result.findings else '<tr><td colspan="3">No findings.</td></tr>'
    return _TEMPLATE.format(
        account=html.escape(result.account_id),
        region=html.escape(result.region),
        generated=html.escape(result.generated_at),
        score=result.score,
        score_color=_score_color(result.score),
        services=html.escape(", ".join(result.services_scanned)),
        cards=cards,
        rows=rows or empty,
    )


def _row(finding) -> str:
    color = _SEVERITY_COLORS[finding.severity.value]
    return f"""<tr>
      <td><span class="pill" style="background:{color}">{finding.severity.value}</span></td>
      <td><code>{html.escape(finding.control_id or finding.type)}</code></td>
      <td><strong>{html.escape(finding.title)}</strong>
          <div class="desc">{html.escape(finding.description)}</div>
          <div class="fix"><em>Fix:</em> {html.escape(finding.remediation)}</div></td>
    </tr>"""


_TEMPLATE = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Endon AI - Data Protection</title>
<style>
  :root {{ color-scheme: light; }}
  body {{ font-family: -apple-system, Segoe UI, Roboto, sans-serif; margin: 0; background: #f4f5f7; color: #1a202c; }}
  header {{ background: #0f1e33; color: #fff; padding: 28px 32px; }}
  header h1 {{ margin: 0 0 6px; font-size: 22px; }}
  header .meta {{ opacity: .8; font-size: 13px; }}
  .wrap {{ max-width: 1040px; margin: 0 auto; padding: 24px 16px 64px; }}
  .summary {{ display: flex; flex-wrap: wrap; gap: 16px; align-items: center; margin: 24px 0; }}
  .score {{ font-size: 40px; font-weight: 700; color: {score_color}; }}
  .cards {{ display: flex; gap: 12px; flex-wrap: wrap; margin-left: auto; }}
  .card {{ background: #fff; border-radius: 8px; padding: 12px 18px; text-align: center; box-shadow: 0 1px 2px rgba(0,0,0,.08); }}
  .card .num {{ font-size: 24px; font-weight: 700; }}
  .card .lbl {{ font-size: 12px; color: #4a5568; }}
  .redact {{ color: #4a5568; font-size: 12px; margin-bottom: 16px; }}
  table {{ width: 100%; border-collapse: collapse; background: #fff; border-radius: 8px; overflow: hidden; box-shadow: 0 1px 2px rgba(0,0,0,.08); }}
  th, td {{ text-align: left; padding: 12px 14px; border-bottom: 1px solid #edf0f3; vertical-align: top; }}
  th {{ background: #f0f2f5; font-size: 12px; text-transform: uppercase; letter-spacing: .04em; color: #4a5568; }}
  .pill {{ color: #fff; padding: 2px 9px; border-radius: 999px; font-size: 11px; font-weight: 700; }}
  code {{ background: #eef1f4; padding: 1px 6px; border-radius: 4px; font-size: 12px; }}
  .desc {{ color: #2d3748; font-size: 13px; margin: 6px 0; font-family: ui-monospace, monospace; }}
  .fix {{ color: #1a202c; font-size: 13px; margin-top: 6px; }}
</style>
</head>
<body>
<header>
  <h1>Endon AI &middot; Data Protection &amp; Secrets</h1>
  <div class="meta">Account {account} &middot; {region} &middot; generated {generated}</div>
</header>
<div class="wrap">
  <div class="summary">
    <div class="score">{score}<span style="font-size:15px;color:#4a5568">/100</span>
      <div style="font-size:13px;color:#4a5568;font-weight:400">Data protection score</div></div>
    <div class="cards">{cards}</div>
  </div>
  <div class="redact">Services scanned: {services}. Secret values are redacted — this report never contains plaintext secrets.</div>
  <table>
    <thead><tr><th>Severity</th><th>Control</th><th>Finding</th></tr></thead>
    <tbody>
    {rows}
    </tbody>
  </table>
</div>
</body>
</html>
"""
