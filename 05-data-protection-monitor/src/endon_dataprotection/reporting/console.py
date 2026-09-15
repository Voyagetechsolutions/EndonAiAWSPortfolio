"""Human-readable data-protection report for the terminal."""

from __future__ import annotations

from endon_core.findings import Severity
from endon_dataprotection.scanner import ScanResult


def render_console(result: ScanResult) -> str:
    lines: list[str] = []
    title = f"ENDON AI - DATA PROTECTION & SECRETS  ({result.account_id} / {result.region})"
    lines.append(title)
    lines.append("=" * len(title))
    counts = result.counts
    summary = "   ".join(
        f"{s.value} {counts[s.value]}" for s in reversed(list(Severity)) if counts[s.value]
    )
    lines.append(f"Findings: {summary or 'none'}")
    lines.append(f"Data protection score: {result.score}/100")
    lines.append("(secret values are redacted; findings never contain the plaintext)")

    for severity in reversed(list(Severity)):
        findings = result.of_severity(severity)
        if not findings:
            continue
        lines.append("")
        lines.append(severity.value)
        lines.append("-" * len(severity.value))
        for finding in sorted(findings, key=lambda f: (f.control_id or "", f.type)):
            lines.append(f"[{finding.control_id}] {finding.title}")
            lines.append(f"    {finding.description}")
            lines.append(f"    fix: {finding.remediation}")
    return "\n".join(lines)
