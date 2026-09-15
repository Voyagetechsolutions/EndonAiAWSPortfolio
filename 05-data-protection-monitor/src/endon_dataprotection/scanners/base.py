"""Scanner registry and helpers for turning secret matches into findings."""

from __future__ import annotations

from collections.abc import Callable, Iterator
from dataclasses import dataclass

from endon_core.findings import Finding, Severity
from endon_dataprotection.context import ScanContext
from endon_dataprotection.secrets import SecretMatch

ScanFn = Callable[[ScanContext], Iterator[Finding]]
SCANNERS: list[ServiceScanner] = []


@dataclass(frozen=True)
class ServiceScanner:
    service: str
    fn: ScanFn

    def __call__(self, ctx: ScanContext) -> Iterator[Finding]:
        return self.fn(ctx)


def scanner(service: str) -> Callable[[ScanFn], ScanFn]:
    def register(fn: ScanFn) -> ScanFn:
        SCANNERS.append(ServiceScanner(service=service, fn=fn))
        return fn

    return register


def max_severity(matches: list[SecretMatch]) -> Severity:
    return max((m.severity for m in matches), key=lambda s: s.rank)


def describe_matches(matches: list[SecretMatch]) -> str:
    """A human-readable, fully redacted summary of the secrets found."""
    return "; ".join(f"{m.name}: {m.redacted}" for m in matches)
