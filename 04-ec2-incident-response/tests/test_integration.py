"""End to end across the platform: Project 1 isolates a host, Project 4 collects evidence.

This is the seam the whole platform is built around. GuardDuty reports a compromised
instance; the Project 1 response engine isolates it and publishes Endon Forensics
Requested; the Project 4 forensics engine, subscribed to that event on the same bus,
collects and preserves the evidence — automatically, in one flow.
"""

from endon_core.config import ResponseMode, Settings
from endon_core.events import DetailType, InMemoryEventBus, Source
from endon_core.store import InMemoryIncidentStore
from endon_detection import samples
from endon_detection.engine import ResponseEngine
from endon_forensics import rules as forensics_rules
from endon_forensics.engine import ForensicsEngine
from endon_forensics.evidence_store import EvidenceStore
from forensics_testkit import ACCOUNT_ID, REGION, create_evidence_bucket

EVIDENCE_BUCKET = "endon-evidence-integration"


def _running_instance(aws):
    ec2 = aws("ec2")
    vpc = ec2.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]["VpcId"]
    subnet = ec2.create_subnet(VpcId=vpc, CidrBlock="10.0.1.0/24")["Subnet"]["SubnetId"]
    sg = ec2.create_security_group(GroupName="web", Description="web", VpcId=vpc)["GroupId"]
    image = ec2.describe_images(Owners=["amazon"])["Images"][0]["ImageId"]
    instance = ec2.run_instances(
        ImageId=image,
        MinCount=1,
        MaxCount=1,
        InstanceType="t3.micro",
        SubnetId=subnet,
        SecurityGroupIds=[sg],
    )["Instances"][0]
    eni = instance["NetworkInterfaces"][0]["NetworkInterfaceId"]
    return samples.instance_resource(
        instance["InstanceId"],
        vpc_id=vpc,
        subnet_id=subnet,
        network_interface_id=eni,
        security_group_ids=[sg],
    ), instance["InstanceId"]


def test_isolation_triggers_automatic_forensic_collection(aws):
    create_evidence_bucket(aws, EVIDENCE_BUCKET)
    bus = InMemoryEventBus(account_id=ACCOUNT_ID, region=REGION)

    response_engine = ResponseEngine(
        settings=Settings(region=REGION, response_mode=ResponseMode.ENFORCE),
        clients=aws,
        store=InMemoryIncidentStore(),
        publisher=bus,
    )
    forensics_engine = ForensicsEngine(
        settings=Settings(region=REGION, evidence_bucket=EVIDENCE_BUCKET),
        clients=aws,
        store=EvidenceStore(EVIDENCE_BUCKET, aws("s3")),
        publisher=bus,
    )
    # Project 4 listens for the forensics request Project 1 will publish.
    bus.subscribe(
        "forensics-requested", forensics_rules.FORENSICS_REQUESTED, forensics_engine.handle_event
    )

    instance_resource, instance_id = _running_instance(aws)
    event = samples.ec2_cryptomining(ACCOUNT_ID, REGION, instance_resource)

    # Project 1 handles the GuardDuty finding: isolates the instance, requests forensics.
    [incident] = response_engine.handle_event(event)

    assert incident.status.value == "CONTAINED"
    assert bus.errors == []

    # Project 4 collected evidence for the same incident, synchronously off the bus.
    [completed] = bus.events(DetailType.FORENSICS_COMPLETED)
    assert completed["source"] == Source.FORENSICS
    assert completed["detail"]["incidentId"] == incident.incident_id
    assert completed["detail"]["status"] == "COLLECTED"
    assert completed["detail"]["snapshotIds"]

    # The manifest is stored, and the instance was preserved (isolated, still running).
    manifest_key = completed["detail"]["manifestKey"]
    aws("s3").head_object(Bucket=EVIDENCE_BUCKET, Key=manifest_key)
    state = aws("ec2").describe_instances(InstanceIds=[instance_id])["Reservations"][0][
        "Instances"
    ][0]["State"]["Name"]
    assert state == "running"

    # And the forensic case verified the isolation Project 1 performed.
    snapshots = aws("ec2").describe_snapshots(SnapshotIds=completed["detail"]["snapshotIds"])[
        "Snapshots"
    ]
    assert all(
        any(
            t["Key"] == "endon:incident-id" and t["Value"] == incident.incident_id
            for t in s["Tags"]
        )
        for s in snapshots
    )


def test_deployed_pattern_matches_project1_forensics_event(aws):
    """The pattern the forensics stack deploys must match the event Project 1 emits."""
    create_evidence_bucket(aws, EVIDENCE_BUCKET)
    bus = InMemoryEventBus(account_id=ACCOUNT_ID, region=REGION)
    forensics_engine = ForensicsEngine(
        settings=Settings(region=REGION, evidence_bucket=EVIDENCE_BUCKET),
        clients=aws,
        store=EvidenceStore(EVIDENCE_BUCKET, aws("s3")),
        publisher=bus,
    )
    bus.subscribe(
        "forensics-requested", forensics_rules.FORENSICS_REQUESTED, forensics_engine.handle_event
    )

    # The exact detail Project 1's RequestForensics action publishes.
    from endon_forensics import handler  # noqa: F401  (ensures package imports cleanly)

    bus.publish(
        Source.DETECTION,
        DetailType.FORENSICS_REQUESTED,
        {
            "incidentId": "INC-PATTERN",
            "accountId": ACCOUNT_ID,
            "region": REGION,
            "instanceId": "i-doesnotexist",
            "instanceArn": f"arn:aws:ec2:{REGION}:{ACCOUNT_ID}:instance/i-doesnotexist",
        },
    )

    assert bus.errors == []
    # Even for a missing instance, a case is opened and a manifest written (status reflects the gaps).
    assert bus.events(DetailType.FORENSICS_COMPLETED)
