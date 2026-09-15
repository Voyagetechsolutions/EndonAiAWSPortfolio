from detection_testkit import ACCOUNT_ID, REGION
from endon_core.config import ResponseMode
from endon_core.events import DetailType, Source
from endon_core.incidents import ActionKind, ActionStatus, IncidentStatus
from endon_detection import rules, samples
from endon_detection.actions import REGISTRY, Action, ActionContext
from endon_detection.normalizers import normalize_event


def key_statuses(aws, user):
    return {k["Status"] for k in aws("iam").list_access_keys(UserName=user)["AccessKeyMetadata"]}


def compromise_event(iam_user):
    return samples.api_calls_from_malicious_ip(
        ACCOUNT_ID, REGION, iam_user["name"], iam_user["keys"][0]
    )


def test_dry_run_records_intent_without_changing_anything(aws, make_engine, iam_user):
    engine = make_engine(mode=ResponseMode.DRY_RUN)

    [incident] = engine.handle_event(compromise_event(iam_user))

    assert incident.status is IncidentStatus.DRY_RUN
    assert key_statuses(aws, iam_user["name"]) == {"Active"}
    disable = next(a for a in incident.actions if a.action == "disable_access_keys")
    assert disable.status is ActionStatus.DRY_RUN
    assert disable.message.startswith("Would deactivate every active access key")


def test_guardduty_sample_findings_never_change_resources(aws, engine, iam_user):
    event = samples.guardduty_event(
        "UnauthorizedAccess:IAMUser/MaliciousIPCaller.Custom",
        account_id=ACCOUNT_ID,
        region=REGION,
        resource=samples.access_key_resource(iam_user["name"], iam_user["keys"][0]),
        severity=8.0,
        title="Sample finding",
        sample=True,
    )

    [incident] = engine.handle_event(event)

    assert incident.status is IncidentStatus.DRY_RUN
    assert key_statuses(aws, iam_user["name"]) == {"Active"}


def test_redelivered_finding_does_not_repeat_the_response(engine, iam_user):
    event = compromise_event(iam_user)

    [first] = engine.handle_event(event)
    [second] = engine.handle_event(event)

    assert second.incident_id == first.incident_id
    assert second.occurrences == 2
    assert len(second.actions) == len(first.actions)
    assert second.timeline[-1].event == "Finding re-observed"


def test_switching_to_enforce_completes_a_dry_run_incident(aws, make_engine, iam_user):
    event = compromise_event(iam_user)
    make_engine(mode=ResponseMode.DRY_RUN).handle_event(event)

    [incident] = make_engine(mode=ResponseMode.ENFORCE).handle_event(event)

    assert incident.status is IncidentStatus.CONTAINED
    assert any(t.event == "Response re-run" for t in incident.timeline)
    assert key_statuses(aws, iam_user["name"]) == {"Inactive"}


def test_failed_action_does_not_stop_the_playbook_and_is_retried(aws, make_engine, iam_user):
    class BrokenQuarantine(Action):
        name = "quarantine_iam_user"
        kind = ActionKind.CONTAIN
        resource_types = ("AwsIamUser",)

        def plan(self, target, ctx: ActionContext):
            return "fail"

        def execute(self, target, ctx: ActionContext):
            raise RuntimeError("simulated IAM outage")

    broken = make_engine(registry={**REGISTRY, "quarantine_iam_user": BrokenQuarantine()})
    event = compromise_event(iam_user)

    [incident] = broken.handle_event(event)

    assert incident.status is IncidentStatus.PARTIALLY_CONTAINED
    assert key_statuses(aws, iam_user["name"]) == {"Inactive"}  # keys still disabled
    failed = next(a for a in incident.actions if a.action == "quarantine_iam_user")
    assert failed.status is ActionStatus.FAILED
    assert "simulated IAM outage" in failed.message

    [retried] = make_engine().handle_event(event)
    assert retried.status is IncidentStatus.CONTAINED
    assert any(t.event == "Response re-run" for t in retried.timeline)


def test_forged_detection_on_the_endon_bus_cannot_lock_out_a_user(aws, engine, iam_user):
    [real] = normalize_event(compromise_event(iam_user))
    forged = {
        "source": Source.POSTURE_SCANNER,
        "detail-type": DetailType.FINDING,
        "detail": {"finding": real.to_dict()},
    }

    [incident] = engine.handle_event(forged)

    assert incident.playbook == "triage"
    assert key_statuses(aws, iam_user["name"]) == {"Active"}


def test_unrelated_events_are_ignored(engine):
    event = {
        "source": "aws.ec2",
        "detail-type": "EC2 Instance State-change Notification",
        "detail": {},
    }
    assert engine.handle_event(event) == []


def test_alert_reports_the_final_outcome(aws, make_engine, iam_user):
    sns, sqs = aws("sns"), aws("sqs")
    topic_arn = sns.create_topic(Name="endon-alerts")["TopicArn"]
    queue_url = sqs.create_queue(QueueName="soc-inbox")["QueueUrl"]
    queue_arn = sqs.get_queue_attributes(QueueUrl=queue_url, AttributeNames=["QueueArn"])[
        "Attributes"
    ]["QueueArn"]
    sns.subscribe(
        TopicArn=topic_arn,
        Protocol="sqs",
        Endpoint=queue_arn,
        Attributes={"RawMessageDelivery": "true"},
    )
    engine = make_engine(alerts_topic_arn=topic_arn)

    [incident] = engine.handle_event(compromise_event(iam_user))

    assert incident.actions[-1].action == "notify"
    assert incident.actions[-1].status is ActionStatus.SUCCEEDED
    body = sqs.receive_message(QueueUrl=queue_url)["Messages"][0]["Body"]
    assert f"Endon AI security incident {incident.incident_id}" in body
    assert "Status:    CONTAINED" in body
    assert "[SUCCEEDED] disable_access_keys" in body


def test_low_severity_findings_without_a_response_are_not_alerted(aws, make_engine, iam_user):
    topic_arn = aws("sns").create_topic(Name="endon-alerts")["TopicArn"]
    engine = make_engine(alerts_topic_arn=topic_arn)
    event = samples.guardduty_event(
        "Discovery:S3/AnomalousBehavior",
        account_id=ACCOUNT_ID,
        region=REGION,
        resource=samples.access_key_resource(iam_user["name"], iam_user["keys"][0]),
        severity=2.0,
        title="Unusual S3 listing",
    )

    [incident] = engine.handle_event(event)

    assert incident.status is IncidentStatus.MONITORING
    assert incident.actions[-1].status is ActionStatus.SKIPPED


def test_incident_updates_are_published_without_raw_finding(engine, bus, iam_user):
    [incident] = engine.handle_event(compromise_event(iam_user))

    [update] = bus.events(DetailType.INCIDENT_UPDATED)
    assert update["source"] == Source.DETECTION
    assert update["detail"]["incident"]["incident_id"] == incident.incident_id
    assert "raw" not in update["detail"]["incident"]["finding"]


def test_end_to_end_through_the_deployed_event_pattern(engine, bus, store, iam_user):
    bus.subscribe("guardduty-to-response-engine", rules.GUARDDUTY_FINDINGS, engine.handle_event)

    bus.put_event(compromise_event(iam_user))

    assert bus.errors == []
    [incident] = store.list()
    assert incident.status is IncidentStatus.CONTAINED
