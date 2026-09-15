from detection_testkit import ACCOUNT_ID, REGION
from endon_core.store import DynamoDBIncidentStore
from endon_detection import handler, samples


def test_lambda_handler_runs_against_platform_resources(aws, monkeypatch, iam_user):
    aws("dynamodb").create_table(
        TableName="endon-incidents",
        KeySchema=[{"AttributeName": "incident_id", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "incident_id", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
    )
    aws("events").create_event_bus(Name="endon-security-bus")
    monkeypatch.setenv("ENDON_RESPONSE_MODE", "enforce")
    monkeypatch.setenv("ENDON_INCIDENTS_TABLE", "endon-incidents")
    monkeypatch.setenv("ENDON_EVENT_BUS", "endon-security-bus")
    monkeypatch.setattr(handler, "_engine", None)
    event = samples.api_calls_from_malicious_ip(
        ACCOUNT_ID, REGION, iam_user["name"], iam_user["keys"][0]
    )

    result = handler.lambda_handler(event, None)

    assert result["processed"] == 1
    [summary] = result["incidents"]
    assert summary["status"] == "CONTAINED"
    stored = DynamoDBIncidentStore("endon-incidents", aws("dynamodb")).get(summary["incidentId"])
    assert stored.status.value == "CONTAINED"
    assert stored.timeline[0].event == "Incident opened"
