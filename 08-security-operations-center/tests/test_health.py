"""Detective-control health: never claim coverage that cannot be confirmed."""

from endon_soc.health import (
    HealthStatus,
    blind_service_count,
    probe_detective_services,
)

REGION = "us-east-1"


def _by_name(services):
    return {s.name: s for s in services}


def test_bare_account_reports_no_false_coverage(aws):
    services = probe_detective_services(aws)
    assert len(services) == 4  # GuardDuty, Security Hub, CloudTrail, AWS Config
    # Nothing is enabled, so nothing may be reported ACTIVE.
    assert all(not s.is_covered for s in services)
    assert blind_service_count(services) == 4


def test_guardduty_enabled_is_reported_active(aws):
    aws("guardduty").create_detector(Enable=True)
    services = _by_name(probe_detective_services(aws))
    assert services["GuardDuty"].status is HealthStatus.ACTIVE
    assert services["GuardDuty"].is_covered


def test_config_recorder_recording_is_reported_active(aws):
    aws("s3").create_bucket(Bucket="endon-config-history")
    config = aws("config")
    config.put_configuration_recorder(
        ConfigurationRecorder={
            "name": "default",
            "roleARN": "arn:aws:iam::123456789012:role/config-role",
            "recordingGroup": {"allSupported": True, "includeGlobalResourceTypes": True},
        }
    )
    config.put_delivery_channel(
        DeliveryChannel={"name": "default", "s3BucketName": "endon-config-history"}
    )
    config.start_configuration_recorder(ConfigurationRecorderName="default")
    services = _by_name(probe_detective_services(aws))
    assert services["AWS Config"].status is HealthStatus.ACTIVE


def test_probe_never_raises_and_enabling_reduces_blind_spots(aws):
    before = blind_service_count(probe_detective_services(aws))
    aws("guardduty").create_detector(Enable=True)
    after = blind_service_count(probe_detective_services(aws))
    assert after == before - 1
