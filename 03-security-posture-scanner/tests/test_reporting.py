import csv
import io
import json

from endon_core.findings import Resource
from endon_core.timeutil import isoformat, utc_now
from endon_posture.context import ScanContext
from endon_posture.reporting import render_console, render_csv, render_html, render_json
from endon_posture.scanner import ScanResult


def _result() -> ScanResult:
    ctx = ScanContext(clients=None, account_id="123456789012", region="us-east-1")
    bucket = Resource(
        "AwsS3Bucket", "arn:aws:s3:::customer-data", details={"bucketName": "customer-data"}
    )
    findings = [
        ctx.finding("S3-001", bucket),
        ctx.finding(
            "EC2-001",
            Resource(
                "AwsEc2SecurityGroup", "arn:aws:ec2:us-east-1:123456789012:security-group/sg-1"
            ),
        ),
        ctx.finding("CT-001", ctx.account_resource()),
    ]
    return ScanResult(
        account_id="123456789012",
        region="us-east-1",
        generated_at=isoformat(utc_now()),
        findings=findings,
        services_scanned=["S3", "EC2", "CloudTrail"],
    )


def test_json_report_round_trips():
    data = json.loads(render_json(_result()))
    assert data["account_id"] == "123456789012"
    assert data["counts"]["CRITICAL"] == 1
    assert len(data["findings"]) == 3
    assert data["controls_evaluated"] >= 20


def test_csv_has_one_row_per_finding():
    rows = list(csv.DictReader(io.StringIO(render_csv(_result()))))
    assert len(rows) == 3
    assert {"severity", "control", "service", "type", "resource"} <= set(rows[0])


def test_html_is_self_contained():
    html = render_html(_result())
    assert html.startswith("<!doctype html>")
    assert "Cloud Security Posture" in html
    assert "http://" not in html.split("<title>")[0]  # no external resources in the head


def test_console_lists_controls_and_score():
    text = render_console(_result())
    assert "Posture score:" in text
    assert "[S3-001]" in text
    assert "customer-data" in text
