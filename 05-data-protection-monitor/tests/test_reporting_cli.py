import json

from dataprotection_testkit import RAW_SECRETS, REGION, build_leaky_account
from endon_dataprotection import cli
from endon_dataprotection.reporting import render_console, render_html, render_json
from endon_dataprotection.scanner import DataProtectionScanner


def _result(aws):
    build_leaky_account(aws)
    return DataProtectionScanner().scan_account(aws, region=REGION)


def test_reports_are_redacted_end_to_end(aws):
    result = _result(aws)
    for render in (render_console, render_html, render_json):
        output = render(result)
        for secret in RAW_SECRETS:
            assert secret not in output, f"{render.__name__} leaked a raw secret"


def test_json_report_round_trips(aws):
    data = json.loads(render_json(_result(aws)))
    assert data["account_id"]
    assert data["counts"]["HIGH"] >= 1 or data["counts"]["CRITICAL"] >= 1


def test_html_is_self_contained(aws):
    html = render_html(_result(aws))
    assert html.startswith("<!doctype html>")
    assert "Data Protection" in html
    assert "http://" not in html.split("<title>")[0]


def test_cli_scan_writes_html(tmp_path, aws):
    build_leaky_account(aws)
    output = tmp_path / "dp.html"
    exit_code = cli.main(["scan", "--region", REGION, "--format", "html", "--output", str(output)])
    assert exit_code == 0
    report = output.read_text(encoding="utf-8")
    assert "Data Protection" in report
    for secret in RAW_SECRETS:
        assert secret not in report


def test_cli_fail_on_returns_nonzero(aws):
    build_leaky_account(aws)
    assert cli.main(["scan", "--region", REGION, "--format", "json", "--fail-on", "HIGH"]) == 1
