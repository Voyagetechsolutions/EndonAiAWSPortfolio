"""Simulate a stolen-credential attack in a dedicated lab account.

Creates a deliberately weak IAM user, then uses its access key the way an attacker
would: discovery calls followed by an attempt to stop CloudTrail logging.

GuardDuty needs a reason to distrust the caller. Adding the IP you attack from to a
GuardDuty custom threat list (``setup --attacker-ip``) makes every call from it raise
UnauthorizedAccess:IAMUser/MaliciousIPCaller.Custom deterministically, and stopping
the trail raises Stealth:IAMUser/CloudTrailLoggingDisabled.

Only run this in an AWS account you own and use for security testing.

    python simulate_credential_compromise.py setup   --lab-account 111122223333 --trail endon-lab-trail \\
        --attacker-ip 203.0.113.10 --threat-list-bucket my-lab-bucket
    python simulate_credential_compromise.py attack  --lab-account 111122223333 --trail endon-lab-trail
    python simulate_credential_compromise.py cleanup --lab-account 111122223333
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import boto3
from botocore.exceptions import ClientError

VICTIM_USER = "endon-lab-victim"
THREAT_LIST_NAME = "endon-lab-threat-list"
THREAT_LIST_KEY = "endon-lab/threat-list.txt"
CREDENTIALS_FILE = Path(__file__).with_name("lab-credentials.json")  # git-ignored


def require_lab_account(expected: str) -> None:
    actual = boto3.client("sts").get_caller_identity()["Account"]
    if actual != expected:
        sys.exit(
            f"Refusing to run: current credentials are for account {actual}, not lab account {expected}."
        )


def victim_policy(account: str, region: str, trail: str) -> dict:
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "Discovery",
                "Effect": "Allow",
                "Action": [
                    "s3:ListAllMyBuckets",
                    "ec2:DescribeInstances",
                    "ec2:DescribeSecurityGroups",
                    "cloudtrail:DescribeTrails",
                ],
                "Resource": "*",
            },
            {
                "Sid": "LogTampering",
                "Effect": "Allow",
                "Action": "cloudtrail:StopLogging",
                "Resource": f"arn:aws:cloudtrail:{region}:{account}:trail/{trail}",
            },
        ],
    }


def setup(args: argparse.Namespace) -> None:
    iam = boto3.client("iam")
    iam.create_user(UserName=VICTIM_USER, Tags=[{"Key": "endon:lab", "Value": "true"}])
    iam.put_user_policy(
        UserName=VICTIM_USER,
        PolicyName="endon-lab-victim-permissions",
        PolicyDocument=json.dumps(victim_policy(args.lab_account, args.region, args.trail)),
    )
    key = iam.create_access_key(UserName=VICTIM_USER)["AccessKey"]
    CREDENTIALS_FILE.write_text(
        json.dumps({"AccessKeyId": key["AccessKeyId"], "SecretAccessKey": key["SecretAccessKey"]})
    )
    print(
        f"Created {VICTIM_USER} with access key {key['AccessKeyId']} (secret saved to {CREDENTIALS_FILE.name})."
    )

    if args.attacker_ip:
        if not args.threat_list_bucket:
            sys.exit("--threat-list-bucket is required with --attacker-ip")
        boto3.client("s3").put_object(
            Bucket=args.threat_list_bucket,
            Key=THREAT_LIST_KEY,
            Body=f"{args.attacker_ip}\n".encode(),
        )
        guardduty = boto3.client("guardduty", region_name=args.region)
        detector = guardduty.list_detectors()["DetectorIds"][0]
        guardduty.create_threat_intel_set(
            DetectorId=detector,
            Name=THREAT_LIST_NAME,
            Format="TXT",
            Location=f"https://s3.amazonaws.com/{args.threat_list_bucket}/{THREAT_LIST_KEY}",
            Activate=True,
        )
        print(
            f"GuardDuty threat list {THREAT_LIST_NAME} now contains {args.attacker_ip}. Allow ~15 minutes to activate."
        )


def attack(args: argparse.Namespace) -> None:
    if not CREDENTIALS_FILE.exists():
        sys.exit("Run setup first.")
    creds = json.loads(CREDENTIALS_FILE.read_text())
    stolen = boto3.session.Session(
        aws_access_key_id=creds["AccessKeyId"],
        aws_secret_access_key=creds["SecretAccessKey"],
        region_name=args.region,
    )
    steps = [
        ("Discovery: list S3 buckets", lambda: stolen.client("s3").list_buckets()),
        ("Discovery: describe EC2 instances", lambda: stolen.client("ec2").describe_instances()),
        (
            "Discovery: describe security groups",
            lambda: stolen.client("ec2").describe_security_groups(),
        ),
        (
            "Discovery: enumerate IAM users (not permitted)",
            lambda: stolen.client("iam").list_users(),
        ),
        (
            "Defense evasion: stop CloudTrail logging",
            lambda: stolen.client("cloudtrail").stop_logging(Name=args.trail),
        ),
    ]
    for description, call in steps:
        try:
            call()
            print(f"  [allowed] {description}")
        except ClientError as exc:
            print(f"  [{exc.response['Error']['Code']}] {description}")
    print(
        "\nWatch for GuardDuty findings, then check the Endon incidents table, alerts and the trail status."
    )


def cleanup(args: argparse.Namespace) -> None:
    iam = boto3.client("iam")
    try:
        for key in iam.list_access_keys(UserName=VICTIM_USER)["AccessKeyMetadata"]:
            iam.delete_access_key(UserName=VICTIM_USER, AccessKeyId=key["AccessKeyId"])
        # Includes the quarantine policy the response engine attached.
        for policy in iam.list_user_policies(UserName=VICTIM_USER)["PolicyNames"]:
            iam.delete_user_policy(UserName=VICTIM_USER, PolicyName=policy)
        iam.delete_user(UserName=VICTIM_USER)
        print(f"Deleted {VICTIM_USER}.")
    except iam.exceptions.NoSuchEntityException:
        print(f"{VICTIM_USER} does not exist.")

    guardduty = boto3.client("guardduty", region_name=args.region)
    for detector in guardduty.list_detectors()["DetectorIds"]:
        for set_id in guardduty.list_threat_intel_sets(DetectorId=detector)["ThreatIntelSetIds"]:
            if (
                guardduty.get_threat_intel_set(DetectorId=detector, ThreatIntelSetId=set_id)["Name"]
                == THREAT_LIST_NAME
            ):
                guardduty.delete_threat_intel_set(DetectorId=detector, ThreatIntelSetId=set_id)
                print(f"Deleted threat list {THREAT_LIST_NAME}.")
    CREDENTIALS_FILE.unlink(missing_ok=True)


def main() -> None:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("command", choices=["setup", "attack", "cleanup"])
    parser.add_argument("--lab-account", required=True, help="account id this must run in")
    parser.add_argument("--region", default="us-east-1")
    parser.add_argument(
        "--trail", default="endon-lab-trail", help="lab CloudTrail trail the attacker stops"
    )
    parser.add_argument("--attacker-ip", help="public IP to add to a GuardDuty custom threat list")
    parser.add_argument("--threat-list-bucket", help="S3 bucket to host the threat list")
    args = parser.parse_args()

    require_lab_account(args.lab_account)
    {"setup": setup, "attack": attack, "cleanup": cleanup}[args.command](args)


if __name__ == "__main__":
    main()
