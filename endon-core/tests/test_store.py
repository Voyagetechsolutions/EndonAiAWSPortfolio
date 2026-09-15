import pytest

from endon_core.findings import Finding, Severity
from endon_core.incidents import Incident, IncidentStatus
from endon_core.store import (
    DynamoDBFindingStore,
    DynamoDBIncidentStore,
    InMemoryFindingStore,
    InMemoryIncidentStore,
)


def create_table(aws, name, key):
    aws("dynamodb").create_table(
        TableName=name,
        KeySchema=[{"AttributeName": key, "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": key, "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
    )


def finding(n: int, severity=Severity.HIGH) -> Finding:
    return Finding(
        source="aws.guardduty",
        type="UnauthorizedAccess:IAMUser/MaliciousIPCaller",
        title=f"Finding {n}",
        severity=severity,
        account_id="123456789012",
        region="us-east-1",
        id=f"finding-{n}",
        updated_at=f"2026-09-15T09:0{n}:00.000Z",
        raw={"score": 5.5},
    )


@pytest.fixture(params=["memory", "dynamodb"])
def incident_store(request, aws):
    if request.param == "memory":
        return InMemoryIncidentStore()
    create_table(aws, "endon-incidents", "incident_id")
    return DynamoDBIncidentStore("endon-incidents", aws("dynamodb"))


@pytest.fixture(params=["memory", "dynamodb"])
def finding_store(request, aws):
    if request.param == "memory":
        return InMemoryFindingStore()
    create_table(aws, "endon-findings", "finding_id")
    return DynamoDBFindingStore("endon-findings", aws("dynamodb"))


def test_incident_create_is_idempotent(incident_store):
    incident = Incident.open(
        finding(1), "compromised-credentials", opened_at="2026-09-15T09:01:00.000Z"
    )

    assert incident_store.create(incident) is True
    assert incident_store.create(incident) is False


def test_incident_save_get_and_list(incident_store):
    first = Incident.open(finding(1), "triage", opened_at="2026-09-15T09:01:00.000Z")
    second = Incident.open(finding(2), "triage", opened_at="2026-09-15T09:02:00.000Z")
    incident_store.create(first)
    incident_store.create(second)

    first.status = IncidentStatus.CONTAINED
    first.log("Containment complete", "keys disabled")
    incident_store.save(first)

    stored = incident_store.get(first.incident_id)
    assert stored.status is IncidentStatus.CONTAINED
    assert stored.timeline[-1].event == "Containment complete"
    assert stored.finding.raw == {"score": 5.5}  # floats survive the round trip
    assert [i.incident_id for i in incident_store.list()] == [second.incident_id, first.incident_id]
    assert incident_store.get("INC-MISSING") is None


def test_finding_store(finding_store):
    finding_store.save(finding(1, Severity.LOW))
    finding_store.save(finding(2))

    assert finding_store.get("finding-1").severity is Severity.LOW
    assert [f.id for f in finding_store.list()] == ["finding-2", "finding-1"]
