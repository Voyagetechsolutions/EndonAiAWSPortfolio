"""Deploys the posture scanner as a scheduled, read-only Lambda.

Its role is read-only across the services it inspects (S3, EC2, RDS, CloudTrail, KMS,
IAM, GuardDuty, Config), plus permission to publish findings to the Endon bus and write
reports to the evidence bucket. Every granted action is a Describe/Get/List. The
infrastructure test enforces that no mutating action is ever granted.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from aws_cdk import Duration, Stack
from aws_cdk import aws_cloudwatch as cloudwatch
from aws_cdk import aws_cloudwatch_actions as cloudwatch_actions
from aws_cdk import aws_events as events
from aws_cdk import aws_events_targets as targets
from aws_cdk import aws_iam as iam
from aws_cdk import aws_lambda as lambda_
from aws_cdk import aws_logs as logs
from constructs import Construct

from lambda_bundle import stage_lambda_source
from platform_stack import PlatformStack

COMPONENT_ROOT = Path(__file__).resolve().parents[1]
REPO_ROOT = COMPONENT_ROOT.parent

# Read-only inspection across every scanned service. AWS Security Audit-style access.
READ_ONLY_ACTIONS = [
    "s3:GetBucketAcl",
    "s3:GetBucketPolicy",
    "s3:GetBucketPolicyStatus",
    "s3:GetBucketPublicAccessBlock",
    "s3:GetBucketLocation",
    "s3:GetBucketLogging",
    "s3:GetBucketVersioning",
    "s3:GetEncryptionConfiguration",
    "s3:ListAllMyBuckets",
    "ec2:DescribeSecurityGroups",
    "ec2:DescribeVolumes",
    "ec2:DescribeInstances",
    "ec2:GetEbsEncryptionByDefault",
    "rds:DescribeDBInstances",
    "cloudtrail:DescribeTrails",
    "cloudtrail:GetTrailStatus",
    "kms:ListKeys",
    "kms:DescribeKey",
    "kms:GetKeyRotationStatus",
    "kms:GetKeyPolicy",
    "iam:GetAccountPasswordPolicy",
    "iam:GetAccountSummary",
    "guardduty:ListDetectors",
    "config:DescribeConfigurationRecorderStatus",
]


class PostureScannerStack(Stack):
    def __init__(
        self,
        scope: Construct,
        construct_id: str,
        *,
        platform: PlatformStack,
        schedule: events.Schedule | None = None,
        **kwargs: Any,
    ) -> None:
        super().__init__(scope, construct_id, **kwargs)

        log_group = logs.LogGroup(
            self,
            "PostureScannerLogs",
            retention=logs.RetentionDays.ONE_YEAR,
            encryption_key=platform.key,
        )
        self.function = lambda_.Function(
            self,
            "PostureScanner",
            description="Endon AI cloud security posture scanner",
            runtime=lambda_.Runtime.PYTHON_3_13,
            architecture=lambda_.Architecture.ARM_64,
            handler="endon_posture.handler.lambda_handler",
            code=lambda_.Code.from_asset(
                stage_lambda_source(
                    "posture-scanner", REPO_ROOT / "endon-core" / "src", COMPONENT_ROOT / "src"
                )
            ),
            memory_size=512,
            timeout=Duration.minutes(5),
            tracing=lambda_.Tracing.ACTIVE,
            log_group=log_group,
            logging_format=lambda_.LoggingFormat.JSON,
            environment={
                "ENDON_EVENT_BUS": platform.bus.event_bus_name,
                "ENDON_EVIDENCE_BUCKET": platform.evidence_bucket.bucket_name,
                "ENDON_POSTURE_PUBLISH_MIN_SEVERITY": "HIGH",
            },
        )

        self.function.add_to_role_policy(
            iam.PolicyStatement(
                sid="ReadOnlySecurityAudit",
                actions=READ_ONLY_ACTIONS,
                resources=[
                    "*"
                ],  # Describe/List/Get APIs are account-wide and not resource-scopable
            )
        )
        platform.bus.grant_put_events_to(self.function)
        platform.evidence_bucket.grant_put(self.function)
        platform.key.grant(self.function, "kms:Decrypt", "kms:GenerateDataKey*")

        events.Rule(
            self,
            "DailyPostureScan",
            description="Run the Endon posture scanner on a schedule",
            schedule=schedule or events.Schedule.rate(Duration.hours(24)),
            targets=[targets.LambdaFunction(self.function)],
        )

        alarm = cloudwatch.Alarm(
            self,
            "PostureScannerErrorsAlarm",
            alarm_description="The Endon posture scanner failed to run",
            metric=self.function.metric_errors(period=Duration.hours(24)),
            threshold=1,
            evaluation_periods=1,
            comparison_operator=cloudwatch.ComparisonOperator.GREATER_THAN_OR_EQUAL_TO_THRESHOLD,
            treat_missing_data=cloudwatch.TreatMissingData.NOT_BREACHING,
        )
        alarm.add_alarm_action(cloudwatch_actions.SnsAction(platform.alerts_topic))
