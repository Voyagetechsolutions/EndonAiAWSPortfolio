"""Deploys the organization structure, the SCP guardrails, and the org audit trail.

This stack is deployed in the **organization management account** with trusted access
enabled. It creates the organizational units, attaches each SCP from the catalog to the
right OUs, and stands up a multi-region organization CloudTrail delivering to an Object
Lock bucket in the Log Archive account.

Two values come from context because they exist before this stack runs:
``-c endon:orgRootId=r-xxxx`` (the organization root) and
``-c endon:organizationId=o-xxxx`` (used in the trail bucket policy).
"""

from __future__ import annotations

from typing import Any

from aws_cdk import CfnOutput, Duration, RemovalPolicy, Stack
from aws_cdk import aws_cloudtrail as cloudtrail
from aws_cdk import aws_iam as iam
from aws_cdk import aws_organizations as organizations
from aws_cdk import aws_s3 as s3
from constructs import Construct

from endon_landingzone.organization import build_endon_organization
from endon_landingzone.scps import SCP_CATALOG


class LandingZoneStack(Stack):
    def __init__(
        self,
        scope: Construct,
        construct_id: str,
        *,
        org_root_id: str | None = None,
        organization_id: str | None = None,
        **kwargs: Any,
    ) -> None:
        super().__init__(scope, construct_id, **kwargs)

        root_id = org_root_id or self.node.try_get_context("endon:orgRootId") or "r-endon"
        org_id = (
            organization_id or self.node.try_get_context("endon:organizationId") or "o-endonexample"
        )

        # --- Organizational units ---------------------------------------------------
        model = build_endon_organization()
        self.ou_ids: dict[str, str] = {"Root": root_id}
        for unit in model.root.children:
            self._create_ou_tree(unit, parent_id=root_id)

        # --- SCP guardrails ---------------------------------------------------------
        for scp in SCP_CATALOG:
            target_ids = [self.ou_ids[name] for name in scp.targets if name in self.ou_ids]
            organizations.CfnPolicy(
                self,
                scp.name,
                name=scp.name,
                description=scp.description,
                type="SERVICE_CONTROL_POLICY",
                content=scp.document,  # CfnPolicy serializes the object to JSON itself
                target_ids=target_ids,
            )

        # --- Organization audit trail ----------------------------------------------
        self._organization_trail(org_id)

        CfnOutput(
            self,
            "SecurityToolingNote",
            value="Deploy the Endon platform into the Security Tooling account",
        )
        for name, ou_id in self.ou_ids.items():
            if name != "Root":
                CfnOutput(self, f"OU{name}Id", value=ou_id)

    def _create_ou_tree(self, unit, parent_id: str) -> None:
        ou = organizations.CfnOrganizationalUnit(
            self, f"OU{unit.name}", name=unit.name, parent_id=parent_id
        )
        self.ou_ids[unit.name] = ou.attr_id
        for child in unit.children:
            self._create_ou_tree(child, parent_id=ou.attr_id)

    def _organization_trail(self, org_id: str) -> None:
        access_logs = s3.Bucket(
            self,
            "TrailAccessLogs",
            encryption=s3.BucketEncryption.S3_MANAGED,
            block_public_access=s3.BlockPublicAccess.BLOCK_ALL,
            enforce_ssl=True,
            removal_policy=RemovalPolicy.RETAIN,
            lifecycle_rules=[s3.LifecycleRule(expiration=Duration.days(400))],
        )
        log_bucket = s3.Bucket(
            self,
            "OrgTrailBucket",
            encryption=s3.BucketEncryption.S3_MANAGED,
            block_public_access=s3.BlockPublicAccess.BLOCK_ALL,
            enforce_ssl=True,
            versioned=True,
            object_lock_enabled=True,
            object_lock_default_retention=s3.ObjectLockRetention.governance(Duration.days(365)),
            server_access_logs_bucket=access_logs,
            server_access_logs_prefix="org-trail/",
            removal_policy=RemovalPolicy.RETAIN,
        )
        # CloudTrail must be able to check the bucket ACL and write logs for the whole org.
        log_bucket.add_to_resource_policy(
            iam.PolicyStatement(
                sid="AWSCloudTrailAclCheck",
                principals=[iam.ServicePrincipal("cloudtrail.amazonaws.com")],
                actions=["s3:GetBucketAcl"],
                resources=[log_bucket.bucket_arn],
            )
        )
        log_bucket.add_to_resource_policy(
            iam.PolicyStatement(
                sid="AWSCloudTrailOrgWrite",
                principals=[iam.ServicePrincipal("cloudtrail.amazonaws.com")],
                actions=["s3:PutObject"],
                resources=[f"{log_bucket.bucket_arn}/AWSLogs/{org_id}/*"],
                conditions={"StringEquals": {"s3:x-amz-acl": "bucket-owner-full-control"}},
            )
        )

        trail = cloudtrail.CfnTrail(
            self,
            "OrganizationTrail",
            trail_name="endon-organization-trail",
            s3_bucket_name=log_bucket.bucket_name,
            is_logging=True,
            is_multi_region_trail=True,
            is_organization_trail=True,
            enable_log_file_validation=True,
            include_global_service_events=True,
        )
        trail.node.add_dependency(log_bucket.policy)
