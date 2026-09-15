import json

import pytest
from moto import mock_aws

from endon_core.aws import ClientFactory

REGION = "us-east-1"


@pytest.fixture(autouse=True)
def aws_credentials(monkeypatch):
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.setenv("AWS_SESSION_TOKEN", "testing")
    monkeypatch.setenv("AWS_DEFAULT_REGION", REGION)
    monkeypatch.delenv("AWS_PROFILE", raising=False)


@pytest.fixture
def aws():
    with mock_aws():
        yield ClientFactory(region=REGION)


def create_managed_policy(iam, name, document):
    return iam.create_policy(PolicyName=name, PolicyDocument=json.dumps(document))["Policy"]["Arn"]


@pytest.fixture
def vulnerable_aws_account(aws):
    """A small over-permissioned account created through the real IAM APIs (moto)."""
    iam = aws("iam")
    # This moto version does not ship the AWS-managed AdministratorAccess as attachable,
    # so use a customer-managed admin-equivalent policy. The analyzer detects admin from
    # the policy document (Action:* on Resource:*), not from the policy ARN.
    admin_arn = create_managed_policy(
        iam,
        "AdminEquivalent",
        {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}],
        },
    )
    wildcard_arn = create_managed_policy(
        iam,
        "DeveloperWildcard",
        {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": "s3:*", "Resource": "*"}],
        },
    )
    escalate_arn = create_managed_policy(
        iam,
        "AttachAnyPolicy",
        {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": "iam:AttachUserPolicy", "Resource": "*"}],
        },
    )

    iam.create_user(UserName="alice-admin")
    iam.attach_user_policy(UserName="alice-admin", PolicyArn=admin_arn)
    iam.create_access_key(UserName="alice-admin")

    iam.create_user(UserName="bob-escalator")
    iam.attach_user_policy(UserName="bob-escalator", PolicyArn=escalate_arn)

    iam.create_user(UserName="dave-wildcard")
    iam.attach_user_policy(UserName="dave-wildcard", PolicyArn=wildcard_arn)

    iam.create_role(
        RoleName="deployer-role",
        AssumeRolePolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {"AWS": "arn:aws:iam::999888777666:root"},
                        "Action": "sts:AssumeRole",
                    }
                ],
            }
        ),
    )
    iam.attach_role_policy(RoleName="deployer-role", PolicyArn=admin_arn)
    return aws
