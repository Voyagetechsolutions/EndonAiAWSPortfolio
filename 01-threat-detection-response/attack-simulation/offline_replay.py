"""Replay a cloud account compromise against a simulated AWS account.

Everything runs locally. moto emulates IAM, EC2, Auto Scaling, S3, CloudTrail, SNS
and SQS; GuardDuty findings are built with the real EventBridge event schema; and
the response engine that runs in Lambda handles them through the same event
patterns that are deployed to AWS. No real AWS account is touched.

    python 01-threat-detection-response/attack-simulation/offline_replay.py
"""

from __future__ import annotations

import os
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [
    str(ROOT / "endon-core" / "src"),
    str(ROOT / "01-threat-detection-response" / "src"),
]

# Fake credentials only: even if moto were bypassed, nothing could reach a real account.
os.environ.update(
    {
        "AWS_ACCESS_KEY_ID": "offline-replay",
        "AWS_SECRET_ACCESS_KEY": "offline-replay",
        "AWS_SESSION_TOKEN": "offline-replay",
        "AWS_DEFAULT_REGION": "us-east-1",
    }
)
os.environ.pop("AWS_PROFILE", None)

from moto import mock_aws  # noqa: E402

from endon_core.aws import ClientFactory  # noqa: E402
from endon_core.config import ResponseMode, Settings  # noqa: E402
from endon_core.events import DetailType, InMemoryEventBus  # noqa: E402
from endon_core.incidents import Incident  # noqa: E402
from endon_core.store import InMemoryIncidentStore  # noqa: E402
from endon_core.timeutil import parse_timestamp  # noqa: E402
from endon_detection import rules, samples  # noqa: E402
from endon_detection.actions.ec2 import QUARANTINE_GROUP_NAME  # noqa: E402
from endon_detection.actions.iam import QUARANTINE_POLICY_NAME  # noqa: E402
from endon_detection.engine import ResponseEngine  # noqa: E402

ACCOUNT_ID = "123456789012"
REGION = "us-east-1"
USER = "ci-deploy-bot"
BUCKET = "acme-customer-exports"
TRAIL = "acme-audit-trail"
ATTACKER_IP = "198.51.100.23"


def heading(text: str) -> None:
    print(f"\n{text}\n{'-' * len(text)}")


def build_account(aws: ClientFactory) -> dict:
    """A small production account: a CI user with a long-lived key, a web server, data, and audit logging."""
    iam = aws("iam")
    iam.create_user(UserName=USER)
    key = iam.create_access_key(UserName=USER)["AccessKey"]["AccessKeyId"]

    ec2 = aws("ec2")
    vpc = ec2.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]["VpcId"]
    subnet = ec2.create_subnet(VpcId=vpc, CidrBlock="10.0.1.0/24")["Subnet"]["SubnetId"]
    web_sg = ec2.create_security_group(GroupName="web", Description="web tier", VpcId=vpc)[
        "GroupId"
    ]
    image = ec2.describe_images(Owners=["amazon"])["Images"][0]["ImageId"]
    instance = ec2.run_instances(
        ImageId=image,
        MinCount=1,
        MaxCount=1,
        InstanceType="t3.micro",
        SubnetId=subnet,
        SecurityGroupIds=[web_sg],
        TagSpecifications=[
            {"ResourceType": "instance", "Tags": [{"Key": "Name", "Value": "web-01"}]}
        ],
    )["Instances"][0]
    eni = instance["NetworkInterfaces"][0]["NetworkInterfaceId"]

    s3 = aws("s3")
    s3.create_bucket(Bucket=BUCKET)
    s3.put_public_access_block(
        Bucket=BUCKET,
        PublicAccessBlockConfiguration={
            k: True
            for k in (
                "BlockPublicAcls",
                "IgnorePublicAcls",
                "BlockPublicPolicy",
                "RestrictPublicBuckets",
            )
        },
    )
    s3.create_bucket(Bucket="acme-audit-logs")
    aws("cloudtrail").create_trail(Name=TRAIL, S3BucketName="acme-audit-logs")
    aws("cloudtrail").start_logging(Name=TRAIL)

    topic = aws("sns").create_topic(Name="endon-security-alerts")["TopicArn"]
    queue_url = aws("sqs").create_queue(QueueName="soc-inbox")["QueueUrl"]
    queue_arn = aws("sqs").get_queue_attributes(QueueUrl=queue_url, AttributeNames=["QueueArn"])[
        "Attributes"
    ]["QueueArn"]
    aws("sns").subscribe(
        TopicArn=topic,
        Protocol="sqs",
        Endpoint=queue_arn,
        Attributes={"RawMessageDelivery": "true"},
    )

    return {
        "key": key,
        "instance_id": instance["InstanceId"],
        "vpc": vpc,
        "subnet": subnet,
        "eni": eni,
        "web_sg": web_sg,
        "topic": topic,
        "queue_url": queue_url,
    }


def run_attack(aws: ClientFactory, env: dict) -> None:
    """What the attacker does with the stolen key before any finding is delivered."""
    heading("PHASE 1 - ATTACK (the attacker moves before any alert fires)")
    iam, ec2, s3 = aws("iam"), aws("ec2"), aws("s3")

    print(f"  [1] Stolen access key {env['key']} used from {ATTACKER_IP} to enumerate S3 buckets")
    print(f"      found: {', '.join(b['Name'] for b in s3.list_buckets()['Buckets'])}")

    backup_key = iam.create_access_key(UserName=USER)["AccessKey"]["AccessKeyId"]
    print(f"  [2] Second access key {backup_key} created for persistence")

    ec2.authorize_security_group_ingress(
        GroupId=env["web_sg"],
        IpPermissions=[
            {
                "IpProtocol": "tcp",
                "FromPort": 22,
                "ToPort": 22,
                "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
            }
        ],
    )
    print(f"  [3] SSH opened to the internet on security group {env['web_sg']}")

    aws("cloudtrail").stop_logging(Name=TRAIL)
    print(f"  [4] CloudTrail trail {TRAIL} stopped to hide further activity")

    s3.delete_public_access_block(Bucket=BUCKET)
    print(f"  [5] S3 Block Public Access removed from {BUCKET}")

    print(f"  [6] Cryptominer started on web-01 ({env['instance_id']})")


def detection_timeline(env: dict) -> list[dict]:
    """The GuardDuty findings this activity produces, in delivery order."""
    instance = samples.instance_resource(
        env["instance_id"],
        vpc_id=env["vpc"],
        subnet_id=env["subnet"],
        network_interface_id=env["eni"],
        security_group_ids=[env["web_sg"]],
    )
    return [
        samples.recon_from_malicious_ip(ACCOUNT_ID, REGION, USER, env["key"]),
        samples.api_calls_from_malicious_ip(ACCOUNT_ID, REGION, USER, env["key"]),
        samples.cloudtrail_logging_disabled(ACCOUNT_ID, REGION, USER, env["key"]),
        samples.s3_block_public_access_disabled(ACCOUNT_ID, REGION, BUCKET, USER, env["key"]),
        samples.ec2_cryptomining(ACCOUNT_ID, REGION, instance),
    ]


def print_incident(incident: Incident) -> None:
    finding = incident.finding
    print(f"\n  {incident.incident_id}  {incident.status:<11} {finding.severity:<8} {finding.type}")
    print(f"  playbook: {incident.playbook}")
    start = parse_timestamp(incident.opened_at)
    for entry in incident.timeline:
        offset = (parse_timestamp(entry.at) - start).total_seconds()
        detail = f" - {entry.detail}" if entry.detail else ""
        print(f"    +{offset:6.3f}s  {entry.event}{detail}")


def own_security_groups(aws: ClientFactory, eni_id: str) -> list[str]:
    ec2 = aws("ec2")
    names = []
    for group in ec2.describe_security_groups()["SecurityGroups"]:
        members = ec2.describe_network_interfaces(
            Filters=[{"Name": "group-id", "Values": [group["GroupId"]]}]
        )
        if any(e["NetworkInterfaceId"] == eni_id for e in members["NetworkInterfaces"]):
            names.append(group["GroupName"])
    return names


def verify(aws: ClientFactory, env: dict, bus: InMemoryEventBus) -> None:
    heading("PHASE 3 - VERIFY THE ACCOUNT STATE THROUGH THE AWS APIs")
    iam, ec2, s3 = aws("iam"), aws("ec2"), aws("s3")

    keys = iam.list_access_keys(UserName=USER)["AccessKeyMetadata"]
    quarantine = QUARANTINE_POLICY_NAME in iam.list_user_policies(UserName=USER)["PolicyNames"]
    trail = aws("cloudtrail").get_trail_status(Name=TRAIL)["IsLogging"]
    bpa = s3.get_public_access_block(Bucket=BUCKET)["PublicAccessBlockConfiguration"]
    groups = own_security_groups(aws, env["eni"])
    protected = ec2.describe_instance_attribute(
        InstanceId=env["instance_id"], Attribute="disableApiTermination"
    )
    web_rules = ec2.describe_security_groups(GroupIds=[env["web_sg"]])["SecurityGroups"][0][
        "IpPermissions"
    ]
    alerts = aws("sqs").receive_message(QueueUrl=env["queue_url"], MaxNumberOfMessages=10)[
        "Messages"
    ]

    rows = [
        (
            f"Access keys for {USER}",
            ", ".join(f"{k['AccessKeyId'][-6:]}={k['Status']}" for k in keys),
        ),
        ("Quarantine deny-all policy", "attached" if quarantine else "missing"),
        (f"CloudTrail {TRAIL}", "logging" if trail else "STOPPED"),
        (
            f"Block Public Access on {BUCKET}",
            "all four settings on" if all(bpa.values()) else "OFF",
        ),
        ("web-01 security groups", ", ".join(groups)),
        (
            "web-01 termination protection",
            "on" if protected["DisableApiTermination"]["Value"] else "off",
        ),
        ("web-01 state", "running (memory preserved for forensics)"),
        (
            "Forensics requests on the Endon bus",
            str(len(bus.events(DetailType.FORENSICS_REQUESTED))),
        ),
        ("Alerts delivered to the SOC queue", str(len(alerts))),
        (
            f"SSH rule on {env['web_sg']}",
            "still open - a posture issue for the Posture Scanner (Project 3)"
            if web_rules
            else "closed",
        ),
    ]
    width = max(len(label) for label, _ in rows) + 3
    for label, value in rows:
        print(f"  {label:.<{width}} {value}")
    if QUARANTINE_GROUP_NAME not in groups:
        raise SystemExit("Verification failed: web-01 is not in the quarantine security group")


def main() -> None:
    with mock_aws():
        aws = ClientFactory(region=REGION)
        env = build_account(aws)

        print("ENDON AI - OFFLINE ATTACK REPLAY")
        print(f"Simulated account {ACCOUNT_ID} ({REGION}). No real AWS resources are used.")
        run_attack(aws, env)

        bus = InMemoryEventBus(account_id=ACCOUNT_ID, region=REGION)
        store = InMemoryIncidentStore()
        engine = ResponseEngine(
            settings=Settings(
                region=REGION, response_mode=ResponseMode.ENFORCE, alerts_topic_arn=env["topic"]
            ),
            clients=aws,
            store=store,
            publisher=bus,
        )
        bus.subscribe("guardduty-to-response-engine", rules.GUARDDUTY_FINDINGS, engine.handle_event)

        heading("PHASE 2 - DETECTION AND AUTOMATED RESPONSE")
        started = time.perf_counter()
        for event in detection_timeline(env):
            bus.put_event(event)
        elapsed = time.perf_counter() - started
        if bus.errors:
            raise SystemExit(f"Delivery errors: {bus.errors}")

        incidents = sorted(store.list(), key=lambda i: i.opened_at)
        for incident in incidents:
            print_incident(incident)

        verify(aws, env, bus)

        heading("SUMMARY")
        statuses: dict[str, int] = {}
        for incident in incidents:
            statuses[incident.status.value] = statuses.get(incident.status.value, 0) + 1
        breakdown = ", ".join(f"{count} {status}" for status, count in sorted(statuses.items()))
        print(f"  {len(incidents)} findings -> {len(incidents)} incidents ({breakdown})")
        print(
            f"  Engine processing time for all findings: {elapsed:.2f}s (local, emulated AWS APIs)"
        )


if __name__ == "__main__":
    main()
