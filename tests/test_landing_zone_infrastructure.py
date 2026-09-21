"""The landing zone stack must create the OUs, attach every SCP, and stand up the org trail."""

import json

import pytest

pytest.importorskip("aws_cdk")

from aws_cdk import App, Environment  # noqa: E402
from aws_cdk.assertions import Match, Template  # noqa: E402

from endon_landingzone.scps import SCP_CATALOG  # noqa: E402
from landing_zone_stack import LandingZoneStack  # noqa: E402


@pytest.fixture(scope="module")
def template():
    app = App()
    stack = LandingZoneStack(
        app,
        "EndonLandingZone",
        org_root_id="r-test",
        organization_id="o-test123456",
        env=Environment(account="111111111111", region="us-east-1"),
    )
    return Template.from_stack(stack)


def test_creates_the_organizational_units(template):
    template.resource_count_is("AWS::Organizations::OrganizationalUnit", 6)
    for name in ("Security", "LogArchive", "Workloads", "Production", "Development", "Sandbox"):
        template.has_resource_properties("AWS::Organizations::OrganizationalUnit", {"Name": name})


def test_attaches_every_scp_in_the_catalog(template):
    template.resource_count_is("AWS::Organizations::Policy", len(SCP_CATALOG))
    for scp in SCP_CATALOG:
        template.has_resource_properties(
            "AWS::Organizations::Policy",
            {"Name": scp.name, "Type": "SERVICE_CONTROL_POLICY"},
        )


def test_scp_content_is_the_catalog_document(template):
    policies = template.find_resources("AWS::Organizations::Policy")
    contents = {
        p["Properties"]["Name"]: _as_document(p["Properties"]["Content"]) for p in policies.values()
    }
    for scp in SCP_CATALOG:
        assert contents[scp.name] == scp.document


def _as_document(content):
    return json.loads(content) if isinstance(content, str) else content


def test_organization_cloudtrail_is_multi_region_and_validated(template):
    template.has_resource_properties(
        "AWS::CloudTrail::Trail",
        {
            "IsOrganizationTrail": True,
            "IsMultiRegionTrail": True,
            "EnableLogFileValidation": True,
            "IsLogging": True,
        },
    )


def test_log_archive_bucket_is_object_locked_and_private(template):
    template.has_resource_properties(
        "AWS::S3::Bucket",
        {
            "ObjectLockEnabled": True,
            "VersioningConfiguration": {"Status": "Enabled"},
            "PublicAccessBlockConfiguration": Match.object_like(
                {"BlockPublicAcls": True, "RestrictPublicBuckets": True}
            ),
        },
    )
