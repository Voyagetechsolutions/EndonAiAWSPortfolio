"""The security score: one explainable number where every point traces to a cause."""

from endon_core.findings import Finding, Severity
from endon_soc.score import (
    BLIND_SERVICE_PENALTY,
    SEVERITY_WEIGHTS,
    grade_for,
    security_score,
    severity_counts,
)

ACCOUNT = "123456789012"
REGION = "us-east-1"


def _finding(severity: Severity, n: int = 0) -> Finding:
    return Finding(
        source="endon.posture-scanner",
        type=f"Posture:Test/Case{n}",
        title=f"case {n}",
        severity=severity,
        account_id=ACCOUNT,
        region=REGION,
        resources=[],
    )


def test_a_clean_account_scores_100_grade_a():
    breakdown = security_score([])
    assert breakdown.score == 100
    assert breakdown.grade == "A"
    assert breakdown.total_penalty == 0


def test_every_point_deducted_traces_to_a_finding():
    findings = [
        _finding(Severity.CRITICAL, 1),
        _finding(Severity.HIGH, 2),
        _finding(Severity.LOW, 3),
    ]
    expected = (
        SEVERITY_WEIGHTS[Severity.CRITICAL]
        + SEVERITY_WEIGHTS[Severity.HIGH]
        + SEVERITY_WEIGHTS[Severity.LOW]
    )
    breakdown = security_score(findings)
    assert breakdown.findings_penalty == expected
    assert breakdown.score == 100 - expected


def test_one_critical_outweighs_a_pile_of_lows():
    # Super-linear weighting: severity must dominate volume.
    one_critical = security_score([_finding(Severity.CRITICAL)])
    twenty_lows = security_score([_finding(Severity.LOW, i) for i in range(20)])
    assert one_critical.score < twenty_lows.score


def test_disabled_detectors_penalize_the_score():
    findings = [_finding(Severity.MEDIUM)]
    without = security_score(findings, blind_services=0)
    with_two_blind = security_score(findings, blind_services=2)
    assert with_two_blind.score == without.score - 2 * BLIND_SERVICE_PENALTY
    assert with_two_blind.blind_penalty == 2 * BLIND_SERVICE_PENALTY


def test_score_floors_at_zero():
    findings = [_finding(Severity.CRITICAL, i) for i in range(10)]  # 250 penalty
    assert security_score(findings).score == 0


def test_severity_counts_include_every_level():
    counts = severity_counts([_finding(Severity.HIGH), _finding(Severity.HIGH, 2)])
    assert counts["HIGH"] == 2
    assert counts["CRITICAL"] == 0
    assert set(counts) == {s.value for s in Severity}


def test_grade_boundaries():
    assert grade_for(90) == "A"
    assert grade_for(89) == "B"
    assert grade_for(70) == "C"
    assert grade_for(60) == "D"
    assert grade_for(59) == "F"
