"""A deliberately leaky account and Macie/Health event builders for the tests and sim.

Plants secrets where they get left in real life — a Lambda's environment variables, an
EC2 instance's user data, an unrotated Secrets Manager secret — plus correctly configured
resources to check for false positives. RAW_SECRETS lists every planted plaintext so tests
can assert none of them ever appears in a finding or report.
"""

from __future__ import annotations

import json
import uuid

from endon_core.timeutil import isoformat, utc_now

REGION = "us-east-1"
ACCOUNT_ID = "123456789012"

# Format-valid, clearly fake secrets. None contains the word "example".
AWS_KEY = "AKIA2E0A8F3B7C9D1E5F"
GITHUB_TOKEN = "ghp_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"
DB_URL = "postgres://svc:pR0d0nlyPWzz9x@db.internal:5432/orders"
PRIVATE_KEY = "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAA\n-----END OPENSSH PRIVATE KEY-----"

RAW_SECRETS = [AWS_KEY, GITHUB_TOKEN, "pR0d0nlyPWzz9x", PRIVATE_KEY]


def _lambda_role(aws) -> str:
    iam = aws("iam")
    try:
        return iam.get_role(RoleName="endon-test-lambda-role")["Role"]["Arn"]
    except iam.exceptions.NoSuchEntityException:
        return iam.create_role(
            RoleName="endon-test-lambda-role",
            AssumeRolePolicyDocument=json.dumps(
                {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Principal": {"Service": "lambda.amazonaws.com"},
                            "Action": "sts:AssumeRole",
                        }
                    ],
                }
            ),
        )["Role"]["Arn"]


def build_leaky_account(aws) -> dict:
    role = _lambda_role(aws)
    lambda_client = aws("lambda")
    lambda_client.create_function(
        FunctionName="checkout",
        Runtime="python3.12",
        Role=role,
        Handler="app.handler",
        Code={"ZipFile": b"def handler(e, c): return 1"},
        Environment={
            "Variables": {
                "DATABASE_URL": DB_URL,
                "GITHUB_TOKEN": GITHUB_TOKEN,
                "LOG_LEVEL": "INFO",  # clean
                "API_KEY": "changeme",  # placeholder, must not flag
            }
        },
    )
    # A clean function: no secrets.
    lambda_client.create_function(
        FunctionName="healthcheck",
        Runtime="python3.12",
        Role=role,
        Handler="app.handler",
        Code={"ZipFile": b"def handler(e, c): return 1"},
        Environment={"Variables": {"LOG_LEVEL": "DEBUG", "AWS_REGION": REGION}},
    )

    ec2 = aws("ec2")
    vpc = ec2.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]["VpcId"]
    subnet = ec2.create_subnet(VpcId=vpc, CidrBlock="10.0.1.0/24")["Subnet"]["SubnetId"]
    image = ec2.describe_images(Owners=["amazon"])["Images"][0]["ImageId"]
    user_data = (
        f"#!/bin/bash\nexport AWS_ACCESS_KEY_ID={AWS_KEY}\necho '{PRIVATE_KEY}' > /root/.ssh/id\n"
    )
    leaky_instance = ec2.run_instances(
        ImageId=image,
        MinCount=1,
        MaxCount=1,
        InstanceType="t3.micro",
        SubnetId=subnet,
        UserData=user_data,
    )["Instances"][0]["InstanceId"]
    clean_instance = ec2.run_instances(
        ImageId=image,
        MinCount=1,
        MaxCount=1,
        InstanceType="t3.micro",
        SubnetId=subnet,
        UserData="#!/bin/bash\nyum update -y\n",
    )["Instances"][0]["InstanceId"]

    sm = aws("secretsmanager")
    sm.create_secret(
        Name="prod/db-password", SecretString="unrotated"
    )  # rotation disabled by default

    return {
        "leaky_lambda": "checkout",
        "clean_lambda": "healthcheck",
        "leaky_instance": leaky_instance,
        "clean_instance": clean_instance,
        "secret_name": "prod/db-password",
    }


def macie_event(bucket: str, *, public: bool, categories: list[str]) -> dict:
    return {
        "version": "0",
        "id": str(uuid.uuid4()),
        "detail-type": "Macie Finding",
        "source": "aws.macie",
        "account": ACCOUNT_ID,
        "time": isoformat(utc_now(), "seconds"),
        "region": REGION,
        "resources": [],
        "detail": {
            "id": f"macie-{bucket}",
            "type": "SensitiveData:S3Object/Personal",
            "accountId": ACCOUNT_ID,
            "region": REGION,
            "severity": {"description": "High", "score": 3},
            "createdAt": isoformat(utc_now()),
            "resourcesAffected": {
                "s3Bucket": {
                    "name": bucket,
                    "arn": f"arn:aws:s3:::{bucket}",
                    "publicAccess": {"effectivePermission": "PUBLIC" if public else "NOT_PUBLIC"},
                },
                "s3Object": {"key": "customers/export.csv"},
            },
            "classificationDetails": {
                "result": {"sensitiveData": [{"category": c, "totalCount": 42} for c in categories]}
            },
        },
    }


def health_credentials_exposed_event(access_key_id: str) -> dict:
    return {
        "version": "0",
        "id": str(uuid.uuid4()),
        "detail-type": "AWS Health Event",
        "source": "aws.health",
        "account": ACCOUNT_ID,
        "time": isoformat(utc_now(), "seconds"),
        "region": "us-east-1",
        "resources": [],
        "detail": {
            "eventTypeCode": "AWS_RISK_CREDENTIALS_EXPOSED",
            "eventTypeCategory": "issue",
            "accountId": ACCOUNT_ID,
            "region": "us-east-1",
            "affectedEntities": [{"entityValue": access_key_id}],
        },
    }
