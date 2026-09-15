from endon_iam_analyzer import cli


def test_scan_writes_an_html_report(tmp_path, vulnerable_aws_account):
    output = tmp_path / "iam.html"

    exit_code = cli.main(
        ["scan", "--region", "us-east-1", "--format", "html", "--output", str(output)]
    )

    assert exit_code == 0
    report = output.read_text(encoding="utf-8")
    assert "IAM Security Assessment" in report
    assert "alice-admin" in report


def test_fail_on_returns_nonzero_when_threshold_met(vulnerable_aws_account, capsys):
    exit_code = cli.main(
        ["scan", "--region", "us-east-1", "--format", "json", "--fail-on", "CRITICAL"]
    )
    assert exit_code == 1


def test_unknown_format_is_rejected(vulnerable_aws_account):
    assert cli.main(["scan", "--region", "us-east-1", "--formats", "pdf"]) == 2
