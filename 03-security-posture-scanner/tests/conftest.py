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


@pytest.fixture
def account_id(aws):
    return aws("sts").get_caller_identity()["Account"]


@pytest.fixture
def ctx(aws, account_id):
    from endon_posture.context import ScanContext

    return ScanContext(clients=aws, account_id=account_id, region=REGION)
