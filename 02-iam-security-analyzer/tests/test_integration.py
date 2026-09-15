"""Cross-project wiring: IAM analyzer findings drive the Project 1 response engine."""

from endon_core.config import ResponseMode, Settings
from endon_core.events import InMemoryEventBus, Source
from endon_core.findings import Severity
from endon_core.store import InMemoryIncidentStore
from endon_detection import rules
from endon_detection.engine import ResponseEngine
from endon_iam_analyzer.analyzer import IamAnalyzer
from endon_iam_analyzer.publish import publish_findings
from iam_testkit import NOW, vulnerable_snapshot

REGION = "us-east-1"


def test_iam_findings_publish_onto_the_endon_bus():
    bus = InMemoryEventBus(account_id="111122223333", region=REGION)
    result = IamAnalyzer().analyze(vulnerable_snapshot(), now=NOW)

    published = publish_findings(result, bus, min_severity=Severity.HIGH)

    events = bus.events("Endon Finding")
    assert published == len(events) > 0
    assert all(e["source"] == Source.IAM_ANALYZER for e in events)
    assert all(e["detail"]["finding"]["severity"] in ("HIGH", "CRITICAL") for e in events)


def test_response_engine_routes_iam_findings_to_review_not_containment(aws):
    bus = InMemoryEventBus(account_id="111122223333", region=REGION)
    store = InMemoryIncidentStore()
    engine = ResponseEngine(
        settings=Settings(region=REGION, response_mode=ResponseMode.ENFORCE),
        clients=aws,
        store=store,
        publisher=bus,
    )
    bus.subscribe("endon-findings-to-response-engine", rules.ENDON_FINDINGS, engine.handle_event)

    result = IamAnalyzer().analyze(vulnerable_snapshot(), now=NOW)
    publish_findings(result, bus, min_severity=Severity.CRITICAL)

    assert bus.errors == []
    incidents = store.list()
    assert incidents, "expected the response engine to open incidents from IAM findings"
    # IAM findings must never trigger principal or host containment - only human review.
    assert all(i.playbook == "iam-risk-review" for i in incidents)
    assert all(i.status.value == "MONITORING" for i in incidents)
