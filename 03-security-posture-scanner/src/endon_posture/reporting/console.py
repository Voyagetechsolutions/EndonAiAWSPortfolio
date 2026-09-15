"""Human-readable posture report for the terminal."""

from __future__ import annotations

from endon_core.findings import Severity
from endon_posture.scanner import ScanResult


def render_console(result: ScanResult) -> str:
    lines: list[str] = []
    title = f"ENDON AI - CLOUD SECURITY POSTURE  ({result.account_id} / {result.region})"
    lines.append(title)
    lines.append("=" * len(title))
    counts = result.counts
    summary = "   ".join(
        f"{s.value} {counts[s.value]}" for s in reversed(list(Severity)) if counts[s.value]
    )
    lines.append(f"Findings: {summary or 'none'}")
    lines.append(f"Posture score: {result.score}/100")
    if result.errors:
        lines.append(f"Services skipped (errors): {', '.join(e['service'] for e in result.errors)}")

    for severity in reversed(list(Severity)):
        findings = result.of_severity(severity)
        if not findings:
            continue
        lines.append("")
        lines.append(severity.value)
        lines.append("-" * len(severity.value))
        for finding in sorted(findings, key=lambda f: (f.control_id or "", f.type)):
            lines.append(f"[{finding.control_id}] {finding.title}")
            for resource in finding.resources:
                lines.append(f"    - {resource.id}")
            lines.append(f"    fix: {finding.remediation}")
    return "\n".join(lines)
