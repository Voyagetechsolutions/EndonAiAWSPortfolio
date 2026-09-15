import pytest
from moto import mock_aws

from endon_core.aws import ClientFactory
from endon_core.config import Settings
from endon_core.events import InMemoryEventBus
from endon_forensics.engine import ForensicsEngine
from endon_forensics.evidence_store import EvidenceStore
from forensics_testkit import EVIDENCE_BUCKET, REGION, create_evidence_bucket


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
def bus():
    return InMemoryEventBus(account_id="123456789012", region=REGION)


@pytest.fixture
def store(aws):
    create_evidence_bucket(aws)
    return EvidenceStore(EVIDENCE_BUCKET, aws("s3"))


@pytest.fixture
def make_engine(aws, bus, store):
    def factory(collectors=None):
        return ForensicsEngine(
            settings=Settings(region=REGION, evidence_bucket=EVIDENCE_BUCKET),
            clients=aws,
            store=store,
            publisher=bus,
            collectors=collectors,
        )

    return factory


@pytest.fixture
def engine(make_engine):
    return make_engine()
