import json

from endon_core.events import DetailType, Source
from endon_forensics.collectors.base import Collector, CollectorContext
from endon_forensics.models import CaseStatus, EvidenceItem, EvidenceStatus
from forensics_testkit import (
    ACCOUNT_ID,
    EVIDENCE_BUCKET,
    forensics_request,
    isolated_instance,
)


def test_collects_a_complete_hashed_case(aws, engine):
    instance = isolated_instance(aws)
    request = forensics_request(instance)

    case = engine.handle_event(request)

    assert case is not None
    assert case.status is CaseStatus.COLLECTED
    kinds = case.collected_kinds()
    assert "metadata" in kinds
    assert "disk-snapshot" in kinds

    # Every collected item is hashed and stored.
    for item in case.evidence:
        if item.collected:
            assert item.sha256 and len(item.sha256) == 64
            assert item.s3_key and item.s3_key.startswith(f"forensics/{case.case_id}/")

    # A tagged EBS snapshot was actually created and left in place.
    assert case.snapshot_ids
    snapshots = aws("ec2").describe_snapshots(SnapshotIds=case.snapshot_ids)["Snapshots"]
    tags = {t["Key"]: t["Value"] for t in snapshots[0]["Tags"]}
    assert tags["endon:evidence"] == "true"
    assert tags["endon:incident-id"] == case.incident_id


def test_manifest_is_written_to_object_lock_bucket(aws, engine):
    instance = isolated_instance(aws)
    case = engine.collect(forensics_request(instance)["detail"])

    assert case.manifest_key == f"forensics/{case.case_id}/manifest.json"
    obj = aws("s3").get_object(Bucket=EVIDENCE_BUCKET, Key=case.manifest_key)
    assert obj["ObjectLockMode"] == "GOVERNANCE"  # immutable evidence
    manifest = json.loads(obj["Body"].read())
    assert manifest["case_id"] == case.case_id
    assert manifest["schema"].startswith("endon.forensics.manifest/")
    # The manifest is the chain of custody: every evidence item with its hash.
    assert len(manifest["evidence"]) == len(case.evidence)
    assert manifest["collector_identity"].startswith("arn:aws:")


def test_isolation_is_verified_as_contained(aws, engine):
    instance = isolated_instance(aws, contained=True)
    case = engine.collect(forensics_request(instance)["detail"])

    assert case.isolation["contained"] is True
    assert case.isolation["terminationProtection"] is True
    assert case.isolation["securityGroups"] == ["endon-quarantine"]


def test_uncontained_instance_is_flagged(aws, engine):
    instance = isolated_instance(aws, contained=False)
    case = engine.collect(forensics_request(instance)["detail"])

    assert case.isolation["contained"] is False
    assert case.isolation["notes"]  # explains why (wrong SG, no termination protection)


def test_volatile_data_skipped_when_instance_not_ssm_reachable(aws, engine):
    instance = isolated_instance(aws)
    case = engine.collect(forensics_request(instance)["detail"])

    volatile = next(e for e in case.evidence if e.kind == "volatile")
    assert volatile.status is EvidenceStatus.SKIPPED
    assert (
        "isolat" in volatile.detail["reason"].lower() or "ssm" in volatile.detail["reason"].lower()
    )


def test_instance_is_never_terminated(aws, engine):
    instance = isolated_instance(aws)
    engine.collect(forensics_request(instance)["detail"])

    state = aws("ec2").describe_instances(InstanceIds=[instance["instance_id"]])["Reservations"][0][
        "Instances"
    ][0]["State"]["Name"]
    assert state == "running"  # evidence preserved


def test_redelivery_does_not_recollect(aws, engine):
    instance = isolated_instance(aws)
    request = forensics_request(instance)

    first = engine.collect(request["detail"])
    snapshots_after_first = aws("ec2").describe_snapshots(OwnerIds=[ACCOUNT_ID])["Snapshots"]

    second = engine.collect(request["detail"])
    snapshots_after_second = aws("ec2").describe_snapshots(OwnerIds=[ACCOUNT_ID])["Snapshots"]

    assert first.status is CaseStatus.COLLECTED
    assert second.status is CaseStatus.SKIPPED
    assert len(snapshots_after_second) == len(snapshots_after_first)  # no duplicate snapshots


def test_completion_event_is_published(aws, engine, bus):
    instance = isolated_instance(aws)
    case = engine.collect(forensics_request(instance)["detail"])

    [event] = bus.events(DetailType.FORENSICS_COMPLETED)
    assert event["source"] == Source.FORENSICS
    assert event["detail"]["caseId"] == case.case_id
    assert event["detail"]["status"] == "COLLECTED"
    assert event["detail"]["snapshotIds"] == case.snapshot_ids
    assert event["detail"]["manifestSha256"] == case.manifest_sha256


def test_one_failing_collector_does_not_lose_the_case(aws, make_engine):
    class BrokenConsole(Collector):
        id = "console-output"
        kind = "console"
        order = 30

        def collect(self, ctx: CollectorContext) -> list[EvidenceItem]:
            raise RuntimeError("simulated console API outage")

    from endon_forensics.collectors import DEFAULT_COLLECTORS

    collectors = [c for c in DEFAULT_COLLECTORS if c.kind != "console"] + [BrokenConsole()]
    engine = make_engine(collectors=collectors)
    instance = isolated_instance(aws)

    case = engine.collect(forensics_request(instance)["detail"])

    # Console is not critical, so the case still completes; the failure is recorded.
    assert case.status is CaseStatus.COLLECTED
    failed = next(e for e in case.evidence if e.status is EvidenceStatus.FAILED)
    assert "simulated console API outage" in failed.detail["error"]


def test_non_forensics_events_are_ignored(engine):
    assert engine.handle_event({"detail-type": "Some Other Event", "detail": {}}) is None
