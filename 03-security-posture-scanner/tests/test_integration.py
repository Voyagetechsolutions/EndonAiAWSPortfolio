"""Cross-project wiring: a posture finding drives the Project 1 response engine.

The scanner sees exposure that GuardDuty never emits an event for (a bucket made public
by a configuration change). It publishes ``Posture:S3/BucketPubliclyAccessible``, and the
Project 1 response engine auto-remediates by re-enabling S3 Block Public Access.
"""

from endon_core.config import ResponseMode, Settings
from endon_core.events import InMemoryEventBus, Source
from endon_core.findings import Severity
from endon_core.store import InMemoryIncidentStore
from endon_detection import rules
from endon_detection.engine import ResponseEngine
from endon_posture.publish import publish_findings
from endon_posture.scanner import PostureScanner
from posture_testkit import REGION


def _public_bucket(aws, name="acme-customer-exports"):
    s3 = aws("s3")
    s3.create_bucket(Bucket=name)
    s3.put_bucket_acl(Bucket=name, ACL="public-read")
    return name


def test_public_bucket_finding_is_auto_remediated_by_project1(aws, account_id):
    bucket = _public_bucket(aws)
    bus = InMemoryEventBus(account_id=account_id, region=REGION)
    store = InMemoryIncidentStore()
    engine = ResponseEngine(
        settings=Settings(region=REGION, response_mode=ResponseMode.ENFORCE),
        clients=aws,
        store=store,
        publisher=bus,
    )
    bus.subscribe("endon-findings-to-response-engine", rules.ENDON_FINDINGS, engine.handle_event)

    # Scan only S3, publish the findings, let the response engine react.
    s3_checks = [c for c in PostureScanner().checks if c.service == "S3"]
    result = PostureScanner(checks=s3_checks).scan_account(aws, region=REGION)
    publish_findings(result, bus, min_severity=Severity.CRITICAL)

    assert bus.errors == []
    incidents = {i.playbook: i for i in store.list()}
    assert "s3-public-exposure" in incidents
    assert incidents["s3-public-exposure"].status.value == "CONTAINED"

    # Block Public Access is now fully enabled on the bucket.
    config = aws("s3").get_public_access_block(Bucket=bucket)["PublicAccessBlockConfiguration"]
    assert all(config.values())


def test_non_public_posture_findings_route_to_review(aws, account_id):
    ec2 = aws("ec2")
    vpc = ec2.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]["VpcId"]
    gid = ec2.create_security_group(GroupName="web", Description="web", VpcId=vpc)["GroupId"]
    ec2.authorize_security_group_ingress(
        GroupId=gid,
        IpPermissions=[
            {
                "IpProtocol": "tcp",
                "FromPort": 22,
                "ToPort": 22,
                "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
            }
        ],
    )
    bus = InMemoryEventBus(account_id=account_id, region=REGION)
    store = InMemoryIncidentStore()
    engine = ResponseEngine(
        settings=Settings(region=REGION, response_mode=ResponseMode.ENFORCE),
        clients=aws,
        store=store,
        publisher=bus,
    )
    bus.subscribe("endon-findings-to-response-engine", rules.ENDON_FINDINGS, engine.handle_event)

    ec2_checks = [c for c in PostureScanner().checks if c.service == "EC2"]
    result = PostureScanner(checks=ec2_checks).scan_account(aws, region=REGION)
    published = publish_findings(result, bus, min_severity=Severity.HIGH)

    assert published >= 1
    assert all(e["source"] == Source.POSTURE_SCANNER for e in bus.events("Endon Finding"))
    # An open SSH group is a posture issue, not an active compromise: triage, don't contain.
    assert all(i.playbook == "triage" for i in store.list())
    assert all(i.status.value == "MONITORING" for i in store.list())
