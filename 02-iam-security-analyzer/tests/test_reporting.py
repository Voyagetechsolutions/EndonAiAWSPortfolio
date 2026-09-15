import csv
import io
import json

from endon_iam_analyzer.analyzer import IamAnalyzer
from endon_iam_analyzer.reporting import render_console, render_csv, render_html, render_json
from iam_testkit import NOW, vulnerable_snapshot


def result():
    return IamAnalyzer().analyze(vulnerable_snapshot(), now=NOW)


def test_json_report_round_trips():
    data = json.loads(render_json(result()))
    assert data["account_id"] == "111122223333"
    assert 0 <= data["score"] <= 100
    assert data["counts"]["CRITICAL"] >= 1
    assert len(data["findings"]) == sum(data["counts"].values())


def test_csv_report_has_one_row_per_finding():
    analysis = result()
    rows = list(csv.DictReader(io.StringIO(render_csv(analysis))))
    assert len(rows) == len(analysis.findings)
    assert {"severity", "type", "control_id", "title"} <= set(rows[0])


def test_html_report_is_self_contained_and_escaped():
    html = render_html(result())
    assert html.startswith("<!doctype html>")
    assert "IAM Security Assessment" in html
    assert "http://" not in html.split("<title>")[0]  # no external resources
    assert "CRITICAL" in html


def test_console_report_lists_score_and_sections():
    text = render_console(result())
    assert "IAM security score:" in text
    assert "CRITICAL" in text
    assert "alice-admin" in text
