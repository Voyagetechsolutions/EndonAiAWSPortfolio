from endon_posture import cli
from posture_testkit import build_vulnerable_environment


def test_scan_writes_html_report(tmp_path, aws):
    build_vulnerable_environment(aws)
    output = tmp_path / "posture.html"

    exit_code = cli.main(
        ["scan", "--region", "us-east-1", "--format", "html", "--output", str(output)]
    )

    assert exit_code == 0
    report = output.read_text(encoding="utf-8")
    assert "Cloud Security Posture" in report
    assert "endon-public" in report


def test_fail_on_returns_nonzero_when_threshold_met(aws):
    build_vulnerable_environment(aws)
    assert cli.main(["scan", "--region", "us-east-1", "--format", "json", "--fail-on", "HIGH"]) == 1


def test_unknown_format_is_rejected(aws):
    assert cli.main(["scan", "--region", "us-east-1", "--formats", "pdf"]) == 2
