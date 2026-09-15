import pytest

from endon_core.events import InMemoryEventBus, matches_pattern

EVENT = {
    "source": "aws.securityhub",
    "detail-type": "Security Hub Findings - Imported",
    "detail": {
        "severity": 8,
        "findings": [
            {"ProductName": "Inspector", "Severity": {"Label": "LOW"}},
            {"ProductName": "Config", "Severity": {"Label": "HIGH"}},
        ],
    },
}


@pytest.mark.parametrize(
    ("pattern", "expected"),
    [
        ({"source": ["aws.securityhub"]}, True),
        ({"source": ["aws.guardduty"]}, False),
        ({"source": [{"prefix": "aws."}]}, True),
        ({"source": [{"anything-but": ["aws.securityhub"]}]}, False),
        ({"detail": {"severity": [{"numeric": [">=", 7, "<", 9]}]}}, True),
        ({"detail": {"severity": [{"numeric": [">", 8]}]}}, False),
        ({"detail": {"missing": [{"exists": False}]}}, True),
        ({"detail": {"severity": [{"exists": False}]}}, False),
        ({"detail": {"findings": {"Severity": {"Label": ["HIGH"]}}}}, True),
        ({"detail": {"findings": {"Severity": {"Label": ["CRITICAL"]}}}}, False),
        ({"detail": {"findings": {"ProductName": [{"anything-but": ["GuardDuty"]}]}}}, True),
        ({"detail": {"nested": {"key": ["value"]}}}, False),
    ],
)
def test_matches_pattern(pattern, expected):
    assert matches_pattern(pattern, EVENT) is expected


def test_bus_delivers_chained_events_without_recursion():
    bus = InMemoryEventBus()
    delivered = []

    def detector(event):
        delivered.append(("detector", event["detail"]["n"]))
        bus.publish("endon.detection", "Endon Incident Updated", {"n": event["detail"]["n"]})

    def dashboard(event):
        delivered.append(("dashboard", event["detail"]["n"]))

    bus.subscribe("detector", {"detail-type": ["Endon Finding"]}, detector)
    bus.subscribe("dashboard", {"detail-type": ["Endon Incident Updated"]}, dashboard)

    bus.publish("endon.posture-scanner", "Endon Finding", {"n": 1})

    assert delivered == [("detector", 1), ("dashboard", 1)]
    assert [e["detail-type"] for e in bus.history] == ["Endon Finding", "Endon Incident Updated"]


def test_bus_records_target_failures_like_a_dead_letter_queue():
    bus = InMemoryEventBus()
    bus.subscribe("broken", {"source": ["endon.soc"]}, lambda event: 1 / 0)
    bus.subscribe("healthy", {"source": ["endon.soc"]}, lambda event: None)

    bus.publish("endon.soc", "Endon Finding", {})

    assert len(bus.errors) == 1
    assert bus.errors[0][0] == "broken"
