"""The benchmark: prove coverage against a plan whose flaws are known in advance.

Same idea as the posture scanner's benchmark (Project 3), one layer earlier — the target is
a Terraform plan, not a running account. Every control in the catalog is planted in the
insecure plan, and the secure plan must produce nothing.
"""

from endon_tfscan import controls
from endon_tfscan.scanner import scan


def test_every_control_fires_on_the_insecure_plan(insecure_plan):
    found = {f.control_id for f in scan(insecure_plan)}
    expected = {c.id for c in controls.all_controls()}
    assert found == expected, f"controls that did not fire: {sorted(expected - found)}"


def test_the_secure_plan_produces_no_findings(secure_plan):
    assert scan(secure_plan) == []


def test_findings_are_sorted_most_severe_first(insecure_plan):
    ranks = [f.severity.rank for f in scan(insecure_plan)]
    assert ranks == sorted(ranks, reverse=True)


def test_findings_are_platform_findings(insecure_plan):
    findings = scan(insecure_plan)
    sample = findings[0]
    assert sample.source == "endon.tfscan"
    assert sample.type.startswith("IaC:")
    assert sample.resources[0].type == "TerraformResource"
    # Converts to ASFF like every other Endon finding, so it can reach Security Hub.
    assert sample.to_asff("arn:aws:securityhub:us-east-1:123456789012:product/x/y")["Id"]


def test_admin_iam_policy_is_flagged_critical(insecure_plan):
    findings = scan(insecure_plan)
    admin = [f for f in findings if f.control_id == "TF-IAM-001"]
    assert admin and admin[0].severity.value == "CRITICAL"
