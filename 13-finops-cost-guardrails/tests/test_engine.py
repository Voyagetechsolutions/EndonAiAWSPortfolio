"""The FinOps + security-cost benchmark, the spike primitive, and the CLI."""

import json
from pathlib import Path

from endon_core.findings import Severity
from endon_finops import cli, controls
from endon_finops.costs import detect_spike
from endon_finops.engine import analyze

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"


def test_every_control_fires_on_the_anomalous_export(anomalous):
    fired = {f.control_id for f in analyze(anomalous)}
    expected = {c.id for c in controls.all_controls()}
    assert fired == expected, f"controls that did not fire: {sorted(expected - fired)}"


def test_the_clean_export_produces_no_findings(clean):
    assert analyze(clean) == []


def test_security_cost_findings_are_high_and_platform_shaped(anomalous):
    findings = analyze(anomalous)
    crypto = next(f for f in findings if f.control_id == "FIN-101")
    assert crypto.source == "endon.finops"
    assert crypto.type == "FinOps:Security/ComputeSpike"
    assert crypto.severity is Severity.HIGH
    assert crypto.to_asff("arn:aws:securityhub:us-east-1:123456789012:product/x/y")["Id"]
    # The two security-cost spikes are the ones that alert at HIGH.
    high = {f.control_id for f in findings if f.severity is Severity.HIGH}
    assert {"FIN-101", "FIN-102"} <= high


def test_spike_primitive():
    flat = [("d1", 40.0), ("d2", 41.0), ("d3", 39.0), ("d4", 40.0)]
    spiking = [("d1", 40.0), ("d2", 41.0), ("d3", 39.0), ("d4", 600.0)]
    tiny = [("d1", 0.5), ("d2", 0.4), ("d3", 8.0)]  # a jump, but below the floor
    assert detect_spike(flat) is None
    hit = detect_spike(spiking)
    assert hit is not None and hit.date == "d4"
    assert detect_spike(tiny, floor=20.0) is None


def test_new_region_needs_no_baseline(anomalous):
    findings = analyze(anomalous)
    region = next(f for f in findings if f.control_id == "FIN-103")
    assert "ap-south-1" in region.resources[0].id


def test_cli_gate(capsys):
    assert cli.main(["analyze", str(FIXTURES / "anomalous.json"), "--fail-on", "HIGH"]) == 1
    out = capsys.readouterr()
    assert "FINOPS + SECURITY-COST" in out.out
    assert "GATE FAILED" in out.err

    assert cli.main(["analyze", str(FIXTURES / "clean.json"), "--fail-on", "HIGH"]) == 0
    assert "PASSED" in capsys.readouterr().out


def test_cli_json(capsys):
    cli.main(["analyze", str(FIXTURES / "anomalous.json"), "--fail-on", "HIGH", "--json"])
    data = json.loads(capsys.readouterr().out)
    assert data["analyzer"] == "endon-finops"
    assert data["by_severity"]["HIGH"] >= 2
