"""Check registry and the shared helpers checks use to build findings."""

from __future__ import annotations

from collections.abc import Callable, Iterator
from dataclasses import dataclass
from datetime import datetime

from endon_core.findings import Domain, Finding, Resource, Severity
from endon_core.timeutil import utc_now
from endon_iam_analyzer.models import AccountSnapshot, Principal

CheckFn = Callable[["CheckContext"], Iterator[Finding]]
CHECKS: list[CheckFn] = []


def check(fn: CheckFn) -> CheckFn:
    CHECKS.append(fn)
    return fn


@dataclass
class CheckContext:
    snapshot: AccountSnapshot
    now: datetime

    @property
    def account_id(self) -> str:
        return self.snapshot.account_id

    @property
    def region(self) -> str:
        return self.snapshot.region

    def finding(
        self,
        *,
        finding_type: str,
        title: str,
        severity: Severity,
        resources: list[Resource],
        description: str,
        remediation: str,
        control_id: str,
        tags: dict[str, str] | None = None,
    ) -> Finding:
        return Finding(
            source="endon.iam-analyzer",
            type=finding_type,
            title=title,
            severity=severity,
            account_id=self.account_id,
            region=self.region,
            resources=resources,
            description=description,
            remediation=remediation,
            control_id=control_id,
            domain=Domain.IAM,
            tags=tags or {},
        )

    def account_resource(self) -> Resource:
        return Resource("AwsAccount", f"AWS::::Account:{self.account_id}")


def lower_severity(severity: Severity, steps: int = 1) -> Severity:
    order = list(Severity)
    return order[max(0, order.index(severity) - steps)]


def protected_note(principal: Principal) -> tuple[Severity, str] | None:
    """If a principal is tagged break-glass, escalation findings are downgraded."""
    if principal.is_protected:
        return lower_severity(
            Severity.CRITICAL
        ), " (principal is tagged endon:protected; treated as break-glass)"
    return None


def now() -> datetime:
    return utc_now()
