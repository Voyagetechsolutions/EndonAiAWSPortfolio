import pytest
from moto import mock_aws

from endon_core.aws import ClientFactory
from endon_soc.app import create_app
from endon_soc.demo import seed_stores
from endon_soc.service import SocService

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
def demo_service():
    incidents, findings = seed_stores()
    return SocService(incidents, findings)


@pytest.fixture
def client(demo_service):
    from fastapi.testclient import TestClient

    return TestClient(create_app(demo_service, account_id="123456789012", region=REGION))
