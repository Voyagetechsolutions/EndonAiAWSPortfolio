"""Render the SOC board as plain text, for the CLI and the offline evidence capture.

The same numbers the web console shows, in a form that drops into a terminal or a screenshot.
ASCII only, so it renders identically on a Windows console (cp1252) and a CI log.
"""

from __future__ import annotations

from endon_soc.service import SocService


def render_console(service: SocService) -> str:
    summary = service.summary()
    lines = [
        "ENDON AI - SECURITY OPERATIONS CENTER",
        "=" * 37,
        "",
        f"Security Score              {summary.security_score:>3}/100   (grade {summary.grade})",
        "",
    ]

    sev = summary.severity_counts
    for level in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        lines.append(f"{level.title() + ' findings':<26}{sev.get(level, 0):>3}")
    lines.append("")

    if summary.services:
        for svc in summary.services:
            lines.append(f"{svc.name:<26}{svc.status}")
        lines.append("")

    lines.append("Recent incidents")
    lines.append("-" * 68)
    incidents = service.incidents(limit=10)
    if not incidents:
        lines.append("  (none)")
    for inc in incidents:
        clock = inc.opened_at.split("T", 1)[1][:5] if "T" in inc.opened_at else inc.opened_at
        title = _clip(inc.finding.title, 34)
        playbook = _clip(inc.playbook, 20)
        lines.append(f"  {clock}  {title:<34}  {playbook:<20}  {inc.status}")

    lines.append("")
    lines.append(
        f"  {summary.total_findings} finding(s), {summary.total_incidents} incident(s), "
        f"{summary.open_incidents} still open. "
        f"-{summary.score_breakdown['findings_penalty']} findings / "
        f"-{summary.score_breakdown['blind_penalty']} blind spots."
    )
    return "\n".join(lines)


def _clip(text: str, width: int) -> str:
    return text if len(text) <= width else text[: width - 3] + "..."
