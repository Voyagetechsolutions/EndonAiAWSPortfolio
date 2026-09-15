"""Run the configuration scanners over an account and summarize the result."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field

from endon_core.aws import ClientFactory
from endon_core.findings import Finding, Severity
from endon_core.log import get_logger
from endon_core.timeutil import isoformat, utc_now
from endon_dataprotection.context import ScanContext
from endon_dataprotection.scanners import SCANNERS, ServiceScanner

logger = get_logger(__name__)

_SCORE_WEIGHTS = {
    Severity.CRITICAL: 25,
    Severity.HIGH: 10,
    Severity.MEDIUM: 3,
    Severity.LOW: 1,
    Severity.INFORMATIONAL: 0,
}


@dataclass
class ScanResult:
    account_id: str
    region: str
    generated_at: str
    findings: list[Finding] = field(default_factory=list)
    services_scanned: list[str] = field(default_factory=list)
    errors: list[dict[str, str]] = field(default_factory=list)

    @property
    def counts(self) -> dict[str, int]:
        counts = {s.value: 0 for s in Severity}
        for finding in self.findings:
            counts[finding.severity.value] += 1
        return counts

    @property
    def score(self) -> int:
        return max(0, 100 - sum(_SCORE_WEIGHTS[f.severity] for f in self.findings))

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
            "services_scanned": self.services_scanned,
            "errors": self.errors,
            "findings": [f.to_dict(include_raw=False) for f in self.by_severity()],
        }


class DataProtectionScanner:
    def __init__(self, scanners: Iterable[ServiceScanner] | None = None) -> None:
        self.scanners = list(scanners) if scanners is not None else list(SCANNERS)

    def scan(
        self, clients: ClientFactory, account_id: str, region: str, partition: str = "aws"
    ) -> ScanResult:
        ctx = ScanContext(
            clients=clients, account_id=account_id, region=region, partition=partition
        )
        findings: list[Finding] = []
        errors: list[dict[str, str]] = []
        for scan in self.scanners:
            try:
                findings.extend(scan(ctx))
            except Exception as exc:  # a denied/absent service must not fail the whole scan
                logger.exception("Data protection scanner failed", extra={"service": scan.service})
                errors.append({"service": scan.service, "error": f"{type(exc).__name__}: {exc}"})
        return ScanResult(
            account_id=account_id,
            region=region,
            generated_at=isoformat(utc_now()),
            findings=_deduplicate(findings),
            services_scanned=sorted({s.service for s in self.scanners}),
            errors=errors,
        )

    def scan_account(self, clients: ClientFactory, region: str) -> ScanResult:
        identity = clients("sts").get_caller_identity()
        partition = (
            "aws-cn"
            if region.startswith("cn-")
            else "aws-us-gov"
            if region.startswith("us-gov-")
            else "aws"
        )
        return self.scan(clients, identity["Account"], region, partition)


def _deduplicate(findings: list[Finding]) -> list[Finding]:
    unique: dict[str, Finding] = {}
    for finding in findings:
        unique.setdefault(finding.id, finding)
    return list(unique.values())
