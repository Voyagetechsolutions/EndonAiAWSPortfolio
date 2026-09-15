from endon_core.config import ResponseMode, Settings
from endon_core.findings import Severity


def test_defaults_to_dry_run():
    assert Settings.from_env({}).response_mode is ResponseMode.DRY_RUN


def test_enforce_must_be_explicit():
    assert (
        Settings.from_env({"ENDON_RESPONSE_MODE": " ENFORCE "}).response_mode
        is ResponseMode.ENFORCE
    )
    assert (
        Settings.from_env({"ENDON_RESPONSE_MODE": "enforced"}).response_mode is ResponseMode.DRY_RUN
    )


def test_reads_platform_resources_from_environment():
    settings = Settings.from_env(
        {
            "AWS_REGION": "eu-west-1",
            "ENDON_EVENT_BUS": "bus",
            "ENDON_INCIDENTS_TABLE": "incidents",
            "ENDON_ALERTS_TOPIC_ARN": "arn:aws:sns:eu-west-1:111122223333:alerts",
            "ENDON_NOTIFY_MIN_SEVERITY": "high",
        }
    )
    assert settings.region == "eu-west-1"
    assert settings.event_bus_name == "bus"
    assert settings.incidents_table == "incidents"
    assert settings.alerts_topic_arn.endswith(":alerts")
    assert settings.notify_min_severity is Severity.HIGH
