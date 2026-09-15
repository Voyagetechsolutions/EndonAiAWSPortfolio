"""Check registry and small networking helpers shared by the service checks.

A check is a function ``(ScanContext) -> Iterator[Finding]``. It fetches the resources
for one service and yields a finding per control violation. Checks are resilient: a
service the caller has no permission for, or that is not in use, is skipped rather than
failing the whole scan.
"""

from __future__ import annotations

from collections.abc import Callable, Iterator
from dataclasses import dataclass
from typing import Any

from endon_core.findings import Finding
from endon_posture.context import ScanContext

CheckFn = Callable[[ScanContext], Iterator[Finding]]
CHECKS: list[ServiceCheck] = []

OPEN_CIDRS = {"0.0.0.0/0", "::/0"}


@dataclass(frozen=True)
class ServiceCheck:
    service: str
    fn: CheckFn

    def __call__(self, ctx: ScanContext) -> Iterator[Finding]:
        return self.fn(ctx)


def check(service: str) -> Callable[[CheckFn], CheckFn]:
    def register(fn: CheckFn) -> CheckFn:
        CHECKS.append(ServiceCheck(service=service, fn=fn))
        return fn

    return register


def permission_matches_port(permission: dict[str, Any], port: int) -> bool:
    """Whether a security-group ip permission covers ``port`` for TCP or all protocols."""
    protocol = str(permission.get("IpProtocol"))
    if protocol == "-1":
        return True
    if protocol not in ("tcp", "6"):
        return False
    from_port = permission.get("FromPort")
    to_port = permission.get("ToPort")
    if from_port is None or to_port is None:
        return True  # whole TCP range
    return from_port <= port <= to_port


def permission_is_open_to_internet(permission: dict[str, Any]) -> bool:
    cidrs = {r.get("CidrIp") for r in permission.get("IpRanges", [])}
    cidrs |= {r.get("CidrIpv6") for r in permission.get("Ipv6Ranges", [])}
    return bool(cidrs & OPEN_CIDRS)


def permission_is_all_protocols(permission: dict[str, Any]) -> bool:
    return str(permission.get("IpProtocol")) == "-1"
