"""A deliberately vulnerable AWS environment and a manifest of what should be found.

This is the scanner's benchmark. It plants a known set of misconfigurations across eight
services through the real AWS APIs (emulated by moto), records exactly which control each
one should trigger, and also builds a handful of correctly configured resources so the
benchmark can prove the scanner does not raise false positives.

Detection rate = (planted controls the scanner reported) / (planted controls).
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field

REGION = "us-east-1"


@dataclass(frozen=True)
class Planted:
    control_id: str
    where: str
    note: str


@dataclass
class Manifest:
    planted: list[Planted] = field(default_factory=list)
    clean_resource_ids: list[str] = field(default_factory=list)

    def add(self, control_id: str, where: str, note: str) -> None:
        self.planted.append(Planted(control_id, where, note))

    @property
    def expected_control_ids(self) -> set[str]:
        return {p.control_id for p in self.planted}


def _hardened_policy(bucket: str, allow_log_delivery: bool) -> str:
    # Principal uses {"AWS": "*"} (a dict) rather than the string "*"; a Deny with a
    # wildcard AWS principal is not public, and the dict form matches how S3 stores it.
    statements = [
        {
            "Sid": "DenyInsecureTransport",
            "Effect": "Deny",
            "Principal": {"AWS": "*"},
            "Action": "s3:*",
            "Resource": [f"arn:aws:s3:::{bucket}", f"arn:aws:s3:::{bucket}/*"],
            "Condition": {"Bool": {"aws:SecureTransport": "false"}},
        }
    ]
    if allow_log_delivery:
        statements.append(
            {
                "Sid": "AllowLogDelivery",
                "Effect": "Allow",
                "Principal": {"Service": "logging.s3.amazonaws.com"},
                "Action": "s3:PutObject",
                "Resource": f"arn:aws:s3:::{bucket}/*",
            }
        )
    return json.dumps({"Version": "2012-10-17", "Statement": statements})


def _harden_bucket(s3, name: str, log_target: str, is_log_target: bool = False) -> None:
    s3.put_bucket_encryption(
        Bucket=name,
        ServerSideEncryptionConfiguration={
            "Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]
        },
    )
    s3.put_bucket_versioning(Bucket=name, VersioningConfiguration={"Status": "Enabled"})
    s3.put_bucket_policy(
        Bucket=name, Policy=_hardened_policy(name, allow_log_delivery=is_log_target)
    )
    s3.put_bucket_logging(
        Bucket=name,
        BucketLoggingStatus={
            "LoggingEnabled": {"TargetBucket": log_target, "TargetPrefix": f"{name}/"}
        },
    )
    s3.put_public_access_block(
        Bucket=name,
        PublicAccessBlockConfiguration={
            "BlockPublicAcls": True,
            "IgnorePublicAcls": True,
            "BlockPublicPolicy": True,
            "RestrictPublicBuckets": True,
        },
    )


def _wildcard_key_policy() -> str:
    return json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "AllowEveryone",
                    "Effect": "Allow",
                    "Principal": {"AWS": "*"},
                    "Action": "kms:*",
                    "Resource": "*",
                }
            ],
        }
    )


def build_vulnerable_environment(clients, region: str = REGION) -> Manifest:  # noqa: PLR0915
    manifest = Manifest()
    _plant_s3(clients, manifest)
    _plant_ec2(clients, manifest, region)
    _plant_rds(clients, manifest)
    _plant_cloudtrail(clients, manifest)
    _plant_kms(clients, manifest)
    _plant_account(manifest)
    return manifest


def _plant_s3(clients, manifest: Manifest) -> None:
    s3 = clients("s3")
    s3.create_bucket(Bucket="endon-logs")
    _harden_bucket(s3, "endon-logs", "endon-logs", is_log_target=True)
    s3.create_bucket(Bucket="endon-trail-logs")
    _harden_bucket(s3, "endon-trail-logs", "endon-logs")
    s3.create_bucket(Bucket="endon-locked")
    _harden_bucket(s3, "endon-locked", "endon-logs")

    s3.create_bucket(Bucket="endon-public")
    s3.put_bucket_acl(Bucket="endon-public", ACL="public-read")
    for control in ("S3-001", "S3-002", "S3-003", "S3-004", "S3-005", "S3-006"):
        manifest.add(
            control, "s3://endon-public", "public bucket, no BPA/encryption/TLS/versioning/logging"
        )

    manifest.clean_resource_ids += [
        "arn:aws:s3:::endon-locked",
        "arn:aws:s3:::endon-logs",
        "arn:aws:s3:::endon-trail-logs",
    ]


def _plant_ec2(clients, manifest: Manifest, region: str) -> None:
    ec2 = clients("ec2")
    vpc = ec2.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]["VpcId"]
    subnet = ec2.create_subnet(VpcId=vpc, CidrBlock="10.0.1.0/24")["Subnet"]["SubnetId"]

    web_sg = ec2.create_security_group(GroupName="endon-web", Description="web", VpcId=vpc)[
        "GroupId"
    ]
    ec2.authorize_security_group_ingress(
        GroupId=web_sg,
        IpPermissions=[
            {
                "IpProtocol": "tcp",
                "FromPort": 22,
                "ToPort": 22,
                "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
            },
            {
                "IpProtocol": "tcp",
                "FromPort": 3389,
                "ToPort": 3389,
                "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
            },
        ],
    )
    manifest.add("EC2-001", web_sg, "SSH open to 0.0.0.0/0")
    manifest.add("EC2-002", web_sg, "RDP open to 0.0.0.0/0")

    open_sg = ec2.create_security_group(GroupName="endon-open", Description="open", VpcId=vpc)[
        "GroupId"
    ]
    ec2.authorize_security_group_ingress(
        GroupId=open_sg, IpPermissions=[{"IpProtocol": "-1", "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}]
    )
    manifest.add("EC2-003", open_sg, "all ports open to 0.0.0.0/0")
    manifest.add("EC2-004", "default sg", "VPC default security group has rules")

    locked_sg = ec2.create_security_group(
        GroupName="endon-locked-sg", Description="locked", VpcId=vpc
    )["GroupId"]
    ec2.authorize_security_group_ingress(
        GroupId=locked_sg,
        IpPermissions=[
            {
                "IpProtocol": "tcp",
                "FromPort": 22,
                "ToPort": 22,
                "IpRanges": [{"CidrIp": "10.0.0.0/8"}],
            }
        ],
    )
    manifest.clean_resource_ids.append(
        f"arn:aws:ec2:{region}:{_account(clients)}:security-group/{locked_sg}"
    )

    az = f"{region}a"
    ec2.create_volume(AvailabilityZone=az, Size=8, Encrypted=False)
    manifest.add("EC2-005", "ebs volume", "unencrypted EBS volume")
    manifest.add("EC2-006", "account", "EBS encryption by default disabled")
    enc_vol = ec2.create_volume(AvailabilityZone=az, Size=8, Encrypted=True)["VolumeId"]
    manifest.clean_resource_ids.append(f"arn:aws:ec2:{region}:{_account(clients)}:volume/{enc_vol}")

    image = ec2.describe_images(Owners=["amazon"])["Images"][0]["ImageId"]
    ec2.run_instances(
        ImageId=image,
        MinCount=1,
        MaxCount=1,
        InstanceType="t3.micro",
        SubnetId=subnet,
        MetadataOptions={"HttpTokens": "optional", "HttpEndpoint": "enabled"},
    )
    manifest.add("EC2-007", "ec2 instance", "IMDSv2 not required")
    safe = ec2.run_instances(
        ImageId=image,
        MinCount=1,
        MaxCount=1,
        InstanceType="t3.micro",
        SubnetId=subnet,
        MetadataOptions={"HttpTokens": "required", "HttpEndpoint": "enabled"},
    )["Instances"][0]["InstanceId"]
    manifest.clean_resource_ids.append(f"arn:aws:ec2:{region}:{_account(clients)}:instance/{safe}")


def _plant_rds(clients, manifest: Manifest) -> None:
    rds = clients("rds")
    rds.create_db_instance(
        DBInstanceIdentifier="endon-vuln-db",
        Engine="mysql",
        DBInstanceClass="db.t3.micro",
        MasterUsername="admin",
        MasterUserPassword="CorrectHorseBattery1",  # noqa: S106
        AllocatedStorage=20,
        PubliclyAccessible=True,
        StorageEncrypted=False,
        BackupRetentionPeriod=0,
    )
    manifest.add("RDS-001", "endon-vuln-db", "publicly accessible")
    manifest.add("RDS-002", "endon-vuln-db", "storage not encrypted")
    manifest.add("RDS-003", "endon-vuln-db", "backups disabled")

    safe = rds.create_db_instance(
        DBInstanceIdentifier="endon-safe-db",
        Engine="mysql",
        DBInstanceClass="db.t3.micro",
        MasterUsername="admin",
        MasterUserPassword="CorrectHorseBattery2",  # noqa: S106
        AllocatedStorage=20,
        PubliclyAccessible=False,
        StorageEncrypted=True,
        BackupRetentionPeriod=7,
    )["DBInstance"]
    manifest.clean_resource_ids.append(safe["DBInstanceArn"])


def _plant_cloudtrail(clients, manifest: Manifest) -> None:
    cloudtrail = clients("cloudtrail")
    cloudtrail.create_trail(
        Name="endon-vuln-trail",
        S3BucketName="endon-trail-logs",
        IsMultiRegionTrail=False,
        EnableLogFileValidation=False,
    )
    # Deliberately never started -> IsLogging false.
    manifest.add("CT-001", "account", "no multi-region trail")
    manifest.add("CT-002", "endon-vuln-trail", "log file validation disabled")
    manifest.add("CT-003", "endon-vuln-trail", "logs not KMS-encrypted")
    manifest.add("CT-004", "endon-vuln-trail", "trail not logging")


def _plant_kms(clients, manifest: Manifest) -> None:
    kms = clients("kms")
    kms.create_key(Description="endon plain key")  # rotation disabled by default
    manifest.add("KMS-001", "kms key", "rotation disabled")
    kms.create_key(Description="endon wildcard key", Policy=_wildcard_key_policy())
    manifest.add("KMS-002", "kms key", "key policy allows Principal '*'")


def _plant_account(manifest: Manifest) -> None:
    # No password policy, root MFA off, no GuardDuty, no Config recorder in a fresh account.
    manifest.add("IAM-001", "account", "no password policy")
    manifest.add("IAM-003", "account", "root MFA disabled")
    manifest.add("DET-001", "account", "GuardDuty not enabled")
    manifest.add("DET-002", "account", "AWS Config not recording")


def _account(clients) -> str:
    return clients("sts").get_caller_identity()["Account"]
