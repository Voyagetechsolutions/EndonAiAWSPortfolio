"""Human-readable report for the terminal, grouped by severity."""

from __future__ import annotations

from endon_core.findings import Severity
from endon_iam_analyzer.analyzer import AnalysisResult


def render_console(result: AnalysisResult) -> str:
    lines: list[str] = []
    title = f"ENDON AI - IAM SECURITY ASSESSMENT  ({result.account_id} / {result.region})"
    lines.append(title)
    lines.append("=" * len(title))
    lines.append(
        f"Users scanned: {result.users_scanned}   "
        f"Roles scanned: {result.roles_scanned}   "
        f"Policies scanned: {result.policies_scanned}"
    )
    counts = result.counts
    lines.append(
        "Findings: "
        + "   ".join(
            f"{s.value} {counts[s.value]}" for s in reversed(list(Severity)) if counts[s.value]
        )
        or "Findings: none"
    )
    lines.append(f"IAM security score: {result.score}/100")

    for severity in reversed(list(Severity)):
        findings = result.of_severity(severity)
        if not findings:
            continue
        lines.append("")
        lines.append(severity.value)
        lines.append("-" * len(severity.value))
        for finding in sorted(findings, key=lambda f: f.type):
            lines.append(f"[{finding.control_id}] {finding.title}")
            for resource in finding.resources:
                lines.append(f"    - {resource.id}")
            lines.append(f"    fix: {finding.remediation}")
    return "\n".join(lines)
