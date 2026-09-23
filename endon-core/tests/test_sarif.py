import json

from endon_core.findings import Domain, Finding, Resource, Severity
from endon_core.sarif import render_sarif, to_sarif


def make_finding(**overrides) -> Finding:
    values = {
        "source": "endon.tfscan",
        "type": "IaC:S3/BucketPubliclyAccessible",
        "title": "Bucket is publicly accessible",
        "severity": Severity.HIGH,
        "account_id": "111122223333",
        "region": "eu-west-1",
        "resources": [Resource("AwsS3Bucket", "arn:aws:s3:::customer-exports")],
        "control_id": "TF-S3-001",
        "domain": Domain.DATA_PROTECTION,
        "remediation": "Enable S3 Block Public Access.",
    }
    values.update(overrides)
    return Finding(**values)


def test_sarif_top_level_shape():
    log = to_sarif([make_finding()], tool_name="endon-tfscan")
    assert log["version"] == "2.1.0"
    assert "$schema" in log
    assert len(log["runs"]) == 1
    assert log["runs"][0]["tool"]["driver"]["name"] == "endon-tfscan"


def test_rule_carries_severity_score_and_remediation():
    log = to_sarif([make_finding()], tool_name="endon-tfscan")
    rule = log["runs"][0]["tool"]["driver"]["rules"][0]
    assert rule["id"] == "TF-S3-001"
    # GitHub reads security-severity to colour the alert; HIGH normalizes to 7.5.
    assert rule["properties"]["security-severity"] == "7.5"
    assert rule["defaultConfiguration"]["level"] == "error"
    assert rule["help"]["text"] == "Enable S3 Block Public Access."
    assert "Data Protection" in rule["properties"]["tags"]


def test_result_maps_to_its_rule_and_resources():
    finding = make_finding()
    result = to_sarif([finding], tool_name="endon-tfscan")["runs"][0]["results"][0]
    assert result["ruleId"] == "TF-S3-001"
    assert result["level"] == "error"
    loc = result["locations"][0]["logicalLocations"][0]
    assert loc["fullyQualifiedName"] == "arn:aws:s3:::customer-exports"
    assert loc["kind"] == "AwsS3Bucket"
    # Stable fingerprint lets a consumer dedup the same issue across runs.
    assert result["partialFingerprints"]["endonFindingId/v1"] == finding.id


def test_severity_levels_span_error_warning_note():
    findings = [
        make_finding(severity=Severity.CRITICAL, resources=[]),
        make_finding(severity=Severity.MEDIUM, resources=[]),
        make_finding(severity=Severity.LOW, resources=[]),
    ]
    levels = [r["level"] for r in to_sarif(findings, tool_name="t")["runs"][0]["results"]]
    assert levels == ["error", "warning", "note"]


def test_one_rule_per_control_even_with_repeated_findings():
    findings = [
        make_finding(resources=[Resource("AwsS3Bucket", "arn:aws:s3:::a")]),
        make_finding(resources=[Resource("AwsS3Bucket", "arn:aws:s3:::b")]),
    ]
    log = to_sarif(findings, tool_name="endon-tfscan")
    assert len(log["runs"][0]["tool"]["driver"]["rules"]) == 1
    assert len(log["runs"][0]["results"]) == 2


def test_findings_without_resources_omit_locations():
    result = to_sarif([make_finding(resources=[])], tool_name="t")["runs"][0]["results"][0]
    assert "locations" not in result


def test_empty_scan_is_valid_sarif():
    log = to_sarif([], tool_name="endon-siem")
    assert log["runs"][0]["results"] == []
    assert log["runs"][0]["tool"]["driver"]["rules"] == []


def test_render_sarif_is_valid_json():
    text = render_sarif([make_finding()], tool_name="endon-tfscan")
    assert json.loads(text)["version"] == "2.1.0"
