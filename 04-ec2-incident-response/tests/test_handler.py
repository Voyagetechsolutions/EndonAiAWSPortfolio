from endon_forensics import handler
from forensics_testkit import (
    EVIDENCE_BUCKET,
    create_evidence_bucket,
    forensics_request,
    isolated_instance,
)


def test_lambda_handler_collects_against_platform_resources(aws, monkeypatch):
    create_evidence_bucket(aws)
    aws("events").create_event_bus(Name="endon-security-bus")
    instance = isolated_instance(aws)

    monkeypatch.setenv("ENDON_EVIDENCE_BUCKET", EVIDENCE_BUCKET)
    monkeypatch.setenv("ENDON_EVENT_BUS", "endon-security-bus")
    monkeypatch.setattr(handler, "_engine", None)

    result = handler.lambda_handler(forensics_request(instance), None)

    assert result["handled"] is True
    assert result["status"] == "COLLECTED"
    assert result["snapshotIds"]
    aws("s3").head_object(Bucket=EVIDENCE_BUCKET, Key=result["manifestKey"])


def test_handler_ignores_unrelated_events(aws, monkeypatch):
    create_evidence_bucket(aws)
    aws("events").create_event_bus(Name="endon-security-bus")
    monkeypatch.setenv("ENDON_EVIDENCE_BUCKET", EVIDENCE_BUCKET)
    monkeypatch.setenv("ENDON_EVENT_BUS", "endon-security-bus")
    monkeypatch.setattr(handler, "_engine", None)

    result = handler.lambda_handler({"detail-type": "Endon Incident Updated", "detail": {}}, None)

    assert result == {"handled": False}
