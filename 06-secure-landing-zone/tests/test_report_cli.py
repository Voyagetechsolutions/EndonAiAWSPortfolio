import json

from endon_landingzone import cli, report
from endon_landingzone.organization import build_endon_organization
from endon_landingzone.report import evaluate_guardrails


def test_all_guardrail_checks_block_the_workload_admin():
    results = evaluate_guardrails(build_endon_organization())
    assert results
    assert all(r.denied for r in results), [r.description for r in results if not r.denied]


def test_console_report_shows_structure_and_proof():
    text = report.render_console()
    assert "ORGANIZATION" in text
    assert "GUARDRAIL PROOF" in text
    assert "DENIED" in text
    assert "dangerous actions blocked by SCP" in text


def test_json_report_round_trips():
    data = json.loads(report.render_json())
    assert data["organization"]["ou"] == "Root"
    assert data["guardrail_proof"]
    assert all(item["denied"] for item in data["guardrail_proof"])


def test_cli_report(capsys):
    assert cli.main(["report"]) == 0
    assert "GUARDRAIL PROOF" in capsys.readouterr().out


def test_cli_report_json(capsys):
    assert cli.main(["report", "--format", "json"]) == 0
    assert json.loads(capsys.readouterr().out)["organization"]["ou"] == "Root"
