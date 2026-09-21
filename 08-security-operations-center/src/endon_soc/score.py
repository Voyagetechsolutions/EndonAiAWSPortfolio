"""The security score: one honest number derived from open findings and detective health.

A dashboard's job is to answer "how exposed are we right now?" in a way a human can act on.
That means the headline number must be *explainable* — every point deducted traces to a
specific finding or a specific blind spot — not a black box. This module is that computation,
and it is the flagship: the score is a pure function of its inputs, so it is fully testable and
never drifts from what the tiles below it show.

Model
-----
Start at 100 and subtract a weight for every open finding, by severity. Weights are
super-linear in severity so that one CRITICAL outweighs a pile of LOWs — the score should move
when something that can actually get you owned appears, not when a linter nitpick does.

On top of that, subtract a fixed penalty for every detective service that is switched off:
being blind is itself a risk, and a green score sitting on top of a disabled GuardDuty is
exactly the false comfort this dashboard exists to prevent.

The score floors at 0 (you cannot be more than fully exposed) and is reported with a letter
grade for at-a-glance triage.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Iterable
from dataclasses import dataclass, field

from endon_core.findings import Finding, Severity

# Super-linear so severity dominates volume: one CRITICAL (25) outranks twenty LOWs (20).
SEVERITY_WEIGHTS: dict[Severity, int] = {
    Severity.CRITICAL: 25,
    Severity.HIGH: 12,
    Severity.MEDIUM: 5,
    Severity.LOW: 1,
    Severity.INFORMATIONAL: 0,
}

# A disabled detective control is a blind spot; each one is worth a HIGH finding of risk.
BLIND_SERVICE_PENALTY = 12

MAX_SCORE = 100


@dataclass(frozen=True)
class ScoreBreakdown:
    """The score plus the arithmetic behind it, so nothing about it is a black box."""

    score: int
    grade: str
    severity_counts: dict[str, int]
    findings_penalty: int
    blind_services: int
    blind_penalty: int

    @property
    def total_penalty(self) -> int:
        return self.findings_penalty + self.blind_penalty

    def to_dict(self) -> dict[str, object]:
        return {
            "score": self.score,
            "grade": self.grade,
            "severity_counts": self.severity_counts,
            "findings_penalty": self.findings_penalty,
            "blind_services": self.blind_services,
            "blind_penalty": self.blind_penalty,
            "total_penalty": self.total_penalty,
        }


def grade_for(score: int) -> str:
    """A-F, the way a SOC lead reads a board at a glance."""
    if score >= 90:
        return "A"
    if score >= 80:
        return "B"
    if score >= 70:
        return "C"
    if score >= 60:
        return "D"
    return "F"


def severity_counts(findings: Iterable[Finding]) -> dict[str, int]:
    """Count findings by severity, always returning every level (zeros included)."""
    counts = Counter(f.severity.value for f in findings)
    return {level.value: counts.get(level.value, 0) for level in Severity}


def security_score(findings: Iterable[Finding], blind_services: int = 0) -> ScoreBreakdown:
    """Compute the security score from open findings and the count of disabled detectors."""
    findings = list(findings)
    counts = severity_counts(findings)
    findings_penalty = sum(SEVERITY_WEIGHTS[f.severity] for f in findings)
    blind_penalty = max(0, blind_services) * BLIND_SERVICE_PENALTY
    score = max(0, MAX_SCORE - findings_penalty - blind_penalty)
    return ScoreBreakdown(
        score=score,
        grade=grade_for(score),
        severity_counts=counts,
        findings_penalty=findings_penalty,
        blind_services=max(0, blind_services),
        blind_penalty=blind_penalty,
    )


@dataclass(frozen=True)
class SeverityTally:
    """Severity counts as an ordered, template-friendly list (CRITICAL first)."""

    items: list[tuple[str, int]] = field(default_factory=list)

    @classmethod
    def from_counts(cls, counts: dict[str, int]) -> SeverityTally:
        order = [s.value for s in reversed(list(Severity))]  # CRITICAL -> INFORMATIONAL
        return cls([(level, counts.get(level, 0)) for level in order])
