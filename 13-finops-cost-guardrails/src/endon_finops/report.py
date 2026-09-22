"""Render cost-guardrail findings for humans and the gate."""

from __future__ import annotations

import json
from collections import Counter
from dataclasses import dataclass

from endon_core.findings import Finding, Severity


@dataclass(frozen=True)
class GateResult:
    findings: list[Finding]
    fail_on: Severity
    blocking: int
    passed: bool

    def to_dict(self) -> dict[str, object]:
        return {
            "analyzer": "endon-finops",
            "fail_on": self.fail_on.value,
            "total": len(self.findings),
            "blocking": self.blocking,
            "passed": self.passed,
            "by_severity": severity_counts(self.findings),
            "findings": [f.to_dict(include_raw=False) for f in self.findings],
        }


def evaluate(findings: list[Finding], fail_on: Severity) -> GateResult:
    blocking = sum(1 for f in findings if f.severity.at_least(fail_on))
    return GateResult(findings, fail_on, blocking, passed=blocking == 0)


def severity_counts(findings: list[Finding]) -> dict[str, int]:
    counts = Counter(f.severity.value for f in findings)
    return {level.value: counts.get(level.value, 0) for level in reversed(list(Severity))}


def render_console(result: GateResult) -> str:
    lines = ["ENDON AI - FINOPS + SECURITY-COST GUARDRAILS", "=" * 44, ""]
    if not result.findings:
        lines.append("  No waste or cost anomalies found.")
    for finding in result.findings:
        mark = ">>" if finding.severity.at_least(result.fail_on) else "  "
        where = finding.resources[0].id if finding.resources else "-"
        lines.append(f"{mark} [{finding.severity.value:<8}] {finding.control_id:<9} {where}")
        lines.append(f"       {finding.description}")

    counts = severity_counts(result.findings)
    summary = "  ".join(f"{lvl} {n}" for lvl, n in counts.items() if n)
    lines += [
        "",
        f"  {len(result.findings)} finding(s){'   ' + summary if summary else ''}",
        f"  Gate (fail-on {result.fail_on.value}): "
        + (f"FAILED — {result.blocking} blocking" if not result.passed else "PASSED"),
    ]
    return "\n".join(lines)


def render_json(result: GateResult) -> str:
    return json.dumps(result.to_dict(), indent=2)
