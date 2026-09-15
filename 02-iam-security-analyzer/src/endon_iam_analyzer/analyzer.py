"""Run every check over a snapshot and summarize the result."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import datetime

from endon_core.findings import Finding, Severity
from endon_core.timeutil import isoformat, utc_now
from endon_iam_analyzer.checks import CHECKS, CheckContext
from endon_iam_analyzer.models import AccountSnapshot

# How many points each finding subtracts from a perfect score of 100.
_SCORE_WEIGHTS = {
    Severity.CRITICAL: 25,
    Severity.HIGH: 10,
    Severity.MEDIUM: 3,
    Severity.LOW: 1,
    Severity.INFORMATIONAL: 0,
}


@dataclass
class AnalysisResult:
    account_id: str
    region: str
    generated_at: str
    findings: list[Finding] = field(default_factory=list)
    users_scanned: int = 0
    roles_scanned: int = 0
    policies_scanned: int = 0

    @property
    def counts(self) -> dict[str, int]:
        counts = {s.value: 0 for s in Severity}
        for finding in self.findings:
            counts[finding.severity.value] += 1
        return counts

    @property
    def score(self) -> int:
        penalty = sum(_SCORE_WEIGHTS[f.severity] for f in self.findings)
        return max(0, 100 - penalty)

    def by_severity(self) -> list[Finding]:
        return sorted(self.findings, key=lambda f: (f.severity.rank, f.type), reverse=True)

    def of_severity(self, severity: Severity) -> list[Finding]:
        return [f for f in self.findings if f.severity is severity]

    def to_dict(self) -> dict:
        return {
            "account_id": self.account_id,
            "region": self.region,
            "generated_at": self.generated_at,
            "score": self.score,
            "counts": self.counts,
            "scanned": {
                "users": self.users_scanned,
                "roles": self.roles_scanned,
                "policies": self.policies_scanned,
            },
            "findings": [f.to_dict(include_raw=False) for f in self.by_severity()],
        }


class IamAnalyzer:
    def __init__(self, checks: Iterable | None = None) -> None:
        self.checks = list(checks) if checks is not None else list(CHECKS)

    def analyze(self, snapshot: AccountSnapshot, now: datetime | None = None) -> AnalysisResult:
        ctx = CheckContext(snapshot=snapshot, now=now or utc_now())
        findings: list[Finding] = []
        for check_fn in self.checks:
            findings.extend(check_fn(ctx))
        return AnalysisResult(
            account_id=snapshot.account_id,
            region=snapshot.region,
            generated_at=isoformat(ctx.now),
            findings=_deduplicate(findings),
            users_scanned=len(snapshot.users),
            roles_scanned=len(snapshot.roles),
            policies_scanned=len(snapshot.policies),
        )


def _deduplicate(findings: list[Finding]) -> list[Finding]:
    unique: dict[str, Finding] = {}
    for finding in findings:
        unique.setdefault(finding.id, finding)
    return list(unique.values())
