"""Deploys the IAM analyzer as a scheduled, read-only Lambda.

The function's role can read IAM and generate the credential and access-advisor
reports, publish findings to the Endon bus, and write HTML/JSON reports to the
evidence bucket. It has no IAM write permission at all - an analyzer that can change
IAM would be exactly the privilege-escalation risk it exists to find. The
infrastructure test enforces that.
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

# Read-only IAM inspection. Every action is a List/Get/Generate that returns data
# and changes nothing.
IAM_READ_ACTIONS = [
    "iam:GetAccountAuthorizationDetails",
    "iam:GenerateCredentialReport",
    "iam:GetCredentialReport",
    "iam:GenerateServiceLastAccessedDetails",
    "iam:GetServiceLastAccessedDetails",
    "iam:GetAccountSummary",
    "iam:GetAccountPasswordPolicy",
    "iam:ListUsers",
    "iam:ListRoles",
    "iam:ListGroups",
    "iam:ListPolicies",
]


class IamAnalyzerStack(Stack):
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
            "IamAnalyzerLogs",
            retention=logs.RetentionDays.ONE_YEAR,
            encryption_key=platform.key,
        )
        self.function = lambda_.Function(
            self,
            "IamAnalyzer",
            description="Endon AI IAM least-privilege and privilege-escalation analyzer",
            runtime=lambda_.Runtime.PYTHON_3_13,
            architecture=lambda_.Architecture.ARM_64,
            handler="endon_iam_analyzer.handler.lambda_handler",
            code=lambda_.Code.from_asset(
                stage_lambda_source(
                    "iam-analyzer", REPO_ROOT / "endon-core" / "src", COMPONENT_ROOT / "src"
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
                "ENDON_IAM_PUBLISH_MIN_SEVERITY": "MEDIUM",
            },
        )

        self.function.add_to_role_policy(
            iam.PolicyStatement(
                sid="ReadOnlyIamInspection",
                actions=IAM_READ_ACTIONS,
                resources=["*"],  # these account-level read APIs do not support resource scoping
            )
        )
        platform.bus.grant_put_events_to(self.function)
        platform.evidence_bucket.grant_put(self.function)
        platform.key.grant(self.function, "kms:Decrypt", "kms:GenerateDataKey*")

        events.Rule(
            self,
            "DailyIamScan",
            description="Run the Endon IAM analyzer on a schedule",
            schedule=schedule or events.Schedule.rate(Duration.hours(24)),
            targets=[targets.LambdaFunction(self.function)],
        )

        alarm = cloudwatch.Alarm(
            self,
            "IamAnalyzerErrorsAlarm",
            alarm_description="The Endon IAM analyzer failed to run",
            metric=self.function.metric_errors(period=Duration.hours(24)),
            threshold=1,
            evaluation_periods=1,
            comparison_operator=cloudwatch.ComparisonOperator.GREATER_THAN_OR_EQUAL_TO_THRESHOLD,
            treat_missing_data=cloudwatch.TreatMissingData.NOT_BREACHING,
        )
        alarm.add_alarm_action(cloudwatch_actions.SnsAction(platform.alerts_topic))
