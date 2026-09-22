"""The detection benchmark, correlation logic, and the CLI."""

import json
from datetime import UTC, datetime
from pathlib import Path

from endon_core.findings import Severity
from endon_siem import cli, detections
from endon_siem.engine import detect
from endon_siem.events import Event

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"


def test_every_detection_fires_on_the_attack_log(attack_events):
    fired = {f.control_id for f in detect(attack_events)}
    expected = {d.id for d in detections.all_detections()}
    assert fired == expected, f"detections that did not fire: {sorted(expected - fired)}"


def test_benign_traffic_is_quiet(benign_events):
    # Normal CI reads, one login, one IP — below every correlation threshold, no single-event hits.
    assert detect(benign_events) == []


def test_detections_carry_attack_technique_and_are_platform_findings(attack_events):
    findings = detect(attack_events)
    root = next(f for f in findings if f.control_id == "SIEM-001")
    assert root.source == "endon.siem"
    assert root.type.startswith("Detection:CloudTrail/")
    assert root.tags["technique"] == "T1078.004"
    assert root.severity is Severity.CRITICAL
    assert root.to_asff("arn:aws:securityhub:us-east-1:123456789012:product/x/y")["Id"]


def _event(
    name: str,
    minute: int,
    second: int = 0,
    ip: str = "203.0.113.10",
    principal: str = "user/mallory",
    failed: bool = False,
    source: str = "s3.amazonaws.com",
) -> Event:
    return Event(
        time=datetime(2026, 9, 21, 10, minute, second, tzinfo=UTC),
        name=name,
        source=source,
        region="us-east-1",
        source_ip=ip,
        error_code="Failed" if failed else None,
        identity_type="IAMUser",
        principal=principal,
        account_id="123456789012",
    )


def test_mass_download_needs_the_threshold_within_the_window():
    below = [_event("GetObject", 0, s) for s in range(0, 40, 10)]  # 4 in 30s -> no
    at = [_event("GetObject", 0, s) for s in range(0, 50, 10)]  # 5 in 40s -> yes
    spread = [_event("GetObject", m) for m in range(0, 10, 2)]  # 5 but over 8 min -> no
    assert detections._mass_download(below) is None
    assert detections._mass_download(at) is not None
    assert detections._mass_download(spread) is None


def test_multi_ip_needs_two_distinct_ips():
    same_ip = [_event("GetObject", 0, 0, ip="1.1.1.1"), _event("GetObject", 1, 0, ip="1.1.1.1")]
    two_ips = [_event("GetObject", 0, 0, ip="1.1.1.1"), _event("GetObject", 1, 0, ip="2.2.2.2")]
    assert detections._multi_ip(same_ip) is None
    assert detections._multi_ip(two_ips) is not None


def test_cli_alerts_on_attack_and_is_quiet_on_benign(capsys):
    assert cli.main(["detect", str(FIXTURES / "attack.json"), "--alert-on", "HIGH"]) == 1
    out = capsys.readouterr()
    assert "CLOUDTRAIL DETECTION" in out.out
    assert "ALERTS" in out.err

    assert cli.main(["detect", str(FIXTURES / "benign.json"), "--alert-on", "HIGH"]) == 0


def test_cli_json(capsys):
    cli.main(["detect", str(FIXTURES / "attack.json"), "--alert-on", "CRITICAL", "--json"])
    data = json.loads(capsys.readouterr().out)
    assert data["engine"] == "endon-siem"
    assert data["total"] >= 11
