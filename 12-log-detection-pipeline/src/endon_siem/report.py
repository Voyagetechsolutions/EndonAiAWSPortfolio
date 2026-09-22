"""Render detections for humans and the alerting gate."""

from __future__ import annotations

import json
from collections import Counter
from dataclasses import dataclass

from endon_core.findings import Finding, Severity


@dataclass(frozen=True)
class GateResult:
    findings: list[Finding]
    alert_on: Severity
    alerting: int
    passed: bool

    def to_dict(self) -> dict[str, object]:
        return {
            "engine": "endon-siem",
            "alert_on": self.alert_on.value,
            "total": len(self.findings),
            "alerting": self.alerting,
            "clean": self.passed,
            "by_severity": severity_counts(self.findings),
            "detections": [f.to_dict(include_raw=False) for f in self.findings],
        }


def evaluate(findings: list[Finding], alert_on: Severity) -> GateResult:
    alerting = sum(1 for f in findings if f.severity.at_least(alert_on))
    return GateResult(findings, alert_on, alerting, passed=alerting == 0)


def severity_counts(findings: list[Finding]) -> dict[str, int]:
    counts = Counter(f.severity.value for f in findings)
    return {level.value: counts.get(level.value, 0) for level in reversed(list(Severity))}


def render_console(result: GateResult) -> str:
    lines = ["ENDON AI - CLOUDTRAIL DETECTION", "=" * 31, ""]
    if not result.findings:
        lines.append("  No detections.")
    for finding in result.findings:
        mark = ">>" if finding.severity.at_least(result.alert_on) else "  "
        when = (finding.first_observed_at or "")[11:19]
        who = finding.resources[0].id if finding.resources else "-"
        who = who.rsplit("/", 1)[-1]
        tech = finding.tags.get("technique", "")
        lines.append(
            f"{mark} {when} [{finding.severity.value:<8}] {finding.control_id:<9} {who}  ({tech})"
        )
        lines.append(f"          {finding.title}")

    counts = severity_counts(result.findings)
    summary = "  ".join(f"{lvl} {n}" for lvl, n in counts.items() if n)
    lines += [
        "",
        f"  {len(result.findings)} detection(s){'   ' + summary if summary else ''}",
        f"  Alert (>= {result.alert_on.value}): "
        + (f"{result.alerting} alerting" if not result.passed else "none"),
    ]
    return "\n".join(lines)


def render_json(result: GateResult) -> str:
    return json.dumps(result.to_dict(), indent=2)
