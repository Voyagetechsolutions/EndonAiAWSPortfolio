from dataprotection_testkit import (
    build_leaky_account,
    health_credentials_exposed_event,
    macie_event,
)
from endon_dataprotection import handler


def _platform(aws):
    aws("events").create_event_bus(Name="endon-security-bus")


def test_event_handler_publishes_macie_finding(aws, monkeypatch):
    _platform(aws)
    monkeypatch.setenv("ENDON_EVENT_BUS", "endon-security-bus")
    monkeypatch.setattr(handler, "_publisher", None)

    result = handler.event_handler(
        macie_event("crm-data", public=True, categories=["CREDENTIALS"]), None
    )

    assert result["published"] == 1
    assert "DataProtection:S3/SensitiveDataPubliclyAccessible" in result["types"]


def test_event_handler_publishes_health_exposure(aws, monkeypatch):
    _platform(aws)
    monkeypatch.setenv("ENDON_EVENT_BUS", "endon-security-bus")
    monkeypatch.setattr(handler, "_publisher", None)

    result = handler.event_handler(health_credentials_exposed_event("AKIA2E0A8F3B7C9D1E5F"), None)

    assert result["published"] == 1
    assert result["types"] == ["DataProtection:IAM/CredentialsExposed"]


def test_scan_handler_runs_and_publishes(aws, monkeypatch):
    _platform(aws)
    build_leaky_account(aws)
    monkeypatch.setenv("ENDON_EVENT_BUS", "endon-security-bus")

    result = handler.scan_handler({}, None)

    assert result["findings"] >= 1
    assert result["published"] >= 1


def test_event_handler_ignores_unrelated_events(aws, monkeypatch):
    _platform(aws)
    monkeypatch.setenv("ENDON_EVENT_BUS", "endon-security-bus")
    monkeypatch.setattr(handler, "_publisher", None)

    result = handler.event_handler(
        {"source": "aws.ec2", "detail-type": "EC2 State-change", "detail": {}}, None
    )

    assert result == {"published": 0}
