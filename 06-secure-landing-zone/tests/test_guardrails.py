"""The guardrail proof: what a workload admin can and cannot do, via the SCP simulator."""

import pytest

from endon_landingzone.organization import build_endon_organization
from endon_landingzone.simulator import Request, ScpSimulator

# A full administrator in the Production account, and the exempt security admin.
PROD_ADMIN = "arn:aws:iam::222222222222:role/Admin"
SECURITY_ADMIN = "arn:aws:iam::333333333333:role/EndonSecurityAdmin"
DEPLOY_ROLE = "arn:aws:iam::222222222222:role/EndonDeploy-pipeline"
ROOT_USER = "arn:aws:iam::222222222222:root"


@pytest.fixture(scope="module")
def production():
    org = build_endon_organization()
    return ScpSimulator(org.effective_scps("Production"))


@pytest.fixture(scope="module")
def sandbox():
    org = build_endon_organization()
    return ScpSimulator(org.effective_scps("Sandbox"))


@pytest.mark.parametrize(
    "action",
    [
        "cloudtrail:StopLogging",
        "cloudtrail:DeleteTrail",
        "config:StopConfigurationRecorder",
        "guardduty:DeleteDetector",
        "securityhub:DisableSecurityHub",
        "s3:PutAccountPublicAccessBlock",
        "organizations:LeaveOrganization",
    ],
)
def test_workload_admin_is_denied_dangerous_actions(production, action):
    decision = production.evaluate(
        Request(action=action, principal_arn=PROD_ADMIN, region="us-east-1")
    )
    assert not decision.allowed, f"{action} should be denied for a workload admin"
    assert decision.denied_by


def test_security_admin_is_exempt_from_logging_and_detection_guardrails(production):
    for action in (
        "cloudtrail:StopLogging",
        "guardduty:DeleteDetector",
        "s3:PutAccountPublicAccessBlock",
    ):
        decision = production.evaluate(Request(action=action, principal_arn=SECURITY_ADMIN))
        assert decision.allowed, f"security admin should be allowed {action}"


def test_region_allowlist_blocks_unapproved_region_but_allows_approved(production):
    denied = production.evaluate(
        Request(action="ec2:RunInstances", principal_arn=PROD_ADMIN, region="ap-southeast-2")
    )
    allowed = production.evaluate(
        Request(action="ec2:RunInstances", principal_arn=PROD_ADMIN, region="us-east-1")
    )
    assert not denied.allowed
    assert allowed.allowed


def test_global_services_are_exempt_from_the_region_lock(production):
    # IAM is global; it must work even though its requests are not in an approved region.
    decision = production.evaluate(
        Request(action="iam:CreateRole", principal_arn=PROD_ADMIN, region="us-west-2")
    )
    assert decision.allowed


def test_public_bucket_acl_is_denied(production):
    public = production.evaluate(
        Request(
            action="s3:PutBucketAcl",
            principal_arn=PROD_ADMIN,
            region="us-east-1",
            context={"s3:x-amz-acl": "public-read"},
        )
    )
    private = production.evaluate(
        Request(
            action="s3:PutBucketAcl",
            principal_arn=PROD_ADMIN,
            region="us-east-1",
            context={"s3:x-amz-acl": "private"},
        )
    )
    assert not public.allowed
    assert private.allowed


def test_endon_platform_is_protected_from_workload_admin_but_not_the_pipeline(production):
    request = Request(
        action="lambda:UpdateFunctionCode",
        principal_arn=PROD_ADMIN,
        region="us-east-1",
        resource="arn:aws:lambda:us-east-1:222222222222:function:EndonResponseEngine",
    )
    assert not production.evaluate(request).allowed
    # The CI/CD deploy role is exempt, so deployments still work.
    from dataclasses import replace

    assert production.evaluate(replace(request, principal_arn=DEPLOY_ROLE)).allowed


def test_root_user_is_denied_everything(production):
    decision = production.evaluate(Request(action="s3:GetObject", principal_arn=ROOT_USER))
    assert not decision.allowed
    assert decision.sid == "DenyAllRootUserActions"


def test_sandbox_is_guardrailed_but_looser_than_production(production, sandbox):
    # Sandbox still enforces region, public S3, no-leave, no-root (inherited from Root)...
    assert sandbox.is_denied(
        Request(action="s3:PutAccountPublicAccessBlock", principal_arn=PROD_ADMIN)
    )
    assert sandbox.is_denied(
        Request(action="ec2:RunInstances", principal_arn=PROD_ADMIN, region="eu-central-1")
    )
    # ...but does not carry the detection-service guardrail that Workloads does.
    guardduty = Request(action="guardduty:DeleteDetector", principal_arn=PROD_ADMIN)
    assert production.is_denied(guardduty)
    assert not sandbox.is_denied(guardduty)


def test_ordinary_actions_are_allowed(production):
    for action in ("s3:GetObject", "dynamodb:PutItem", "ec2:DescribeInstances"):
        assert production.evaluate(
            Request(action=action, principal_arn=PROD_ADMIN, region="us-east-1")
        ).allowed
