"""Security gates the pipeline runs, reusing the platform's own analyzers.

The point of a secure pipeline is not just keyless auth — it is that security checks are
part of the build. These gates run the IAM analyzer (Project 2) before deploy and the
posture scanner (Project 3) after, failing the build on findings at or above a threshold.
"""

from __future__ import annotations

from dataclasses import dataclass

from endon_core.aws import ClientFactory
from endon_core.findings import Severity
from endon_iam_analyzer.analyzer import IamAnalyzer
from endon_iam_analyzer.snapshot import build_snapshot
from endon_posture.scanner import PostureScanner


@dataclass
class GateResult:
    name: str
    passed: bool
    findings: int
    blocking: int
    threshold: str
    summary: str

    def to_dict(self) -> dict:
        return {
            "gate": self.name,
            "passed": self.passed,
            "findings": self.findings,
            "blocking": self.blocking,
            "threshold": self.threshold,
            "summary": self.summary,
        }


def iam_gate(
    clients: ClientFactory, region: str, fail_on: Severity = Severity.CRITICAL
) -> GateResult:
    snapshot = build_snapshot(clients, region=region)
    result = IamAnalyzer().analyze(snapshot)
    blocking = [f for f in result.findings if f.severity.at_least(fail_on)]
    return GateResult(
        name="iam-analyzer",
        passed=not blocking,
        findings=len(result.findings),
        blocking=len(blocking),
        threshold=fail_on.value,
        summary=f"IAM security score {result.score}/100; {len(blocking)} finding(s) at/above {fail_on}",
    )


def posture_gate(
    clients: ClientFactory, region: str, fail_on: Severity = Severity.HIGH
) -> GateResult:
    result = PostureScanner().scan_account(clients, region=region)
    blocking = [f for f in result.findings if f.severity.at_least(fail_on)]
    return GateResult(
        name="posture-scanner",
        passed=not blocking,
        findings=len(result.findings),
        blocking=len(blocking),
        threshold=fail_on.value,
        summary=f"Posture score {result.score}/100; {len(blocking)} finding(s) at/above {fail_on}",
    )
