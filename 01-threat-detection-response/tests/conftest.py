import pytest
from moto import mock_aws

from detection_testkit import ACCOUNT_ID, REGION, describe_instance
from endon_core.aws import ClientFactory
from endon_core.config import ResponseMode, Settings
from endon_core.events import InMemoryEventBus
from endon_core.store import InMemoryIncidentStore
from endon_detection.engine import ResponseEngine


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
    return InMemoryEventBus(account_id=ACCOUNT_ID, region=REGION)


@pytest.fixture
def store():
    return InMemoryIncidentStore()


@pytest.fixture
def make_engine(aws, bus, store):
    def factory(mode=ResponseMode.ENFORCE, registry=None, guardrails=None, **settings):
        return ResponseEngine(
            settings=Settings(region=REGION, response_mode=mode, **settings),
            clients=aws,
            store=store,
            publisher=bus,
            registry=registry,
            guardrails=guardrails,
        )

    return factory


@pytest.fixture
def engine(make_engine):
    return make_engine()


@pytest.fixture
def iam_user(aws):
    iam = aws("iam")
    iam.create_user(UserName="ci-deploy-bot")
    keys = [
        iam.create_access_key(UserName="ci-deploy-bot")["AccessKey"]["AccessKeyId"]
        for _ in range(2)
    ]
    return {"name": "ci-deploy-bot", "keys": keys}


@pytest.fixture
def network(aws):
    ec2 = aws("ec2")
    vpc_id = ec2.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]["VpcId"]
    subnet_id = ec2.create_subnet(VpcId=vpc_id, CidrBlock="10.0.1.0/24")["Subnet"]["SubnetId"]
    group_id = ec2.create_security_group(GroupName="web", Description="web tier", VpcId=vpc_id)[
        "GroupId"
    ]
    ec2.authorize_security_group_ingress(
        GroupId=group_id,
        IpPermissions=[
            {
                "IpProtocol": "tcp",
                "FromPort": 22,
                "ToPort": 22,
                "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
            }
        ],
    )
    image_id = ec2.describe_images(Owners=["amazon"])["Images"][0]["ImageId"]
    return {"vpc_id": vpc_id, "subnet_id": subnet_id, "group_id": group_id, "image_id": image_id}


@pytest.fixture
def ec2_instance(aws, network):
    instance = aws("ec2").run_instances(
        ImageId=network["image_id"],
        MinCount=1,
        MaxCount=1,
        InstanceType="t3.micro",
        SubnetId=network["subnet_id"],
        SecurityGroupIds=[network["group_id"]],
    )["Instances"][0]
    return describe_instance(aws, instance["InstanceId"])
