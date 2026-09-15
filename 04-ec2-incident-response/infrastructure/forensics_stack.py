"""Deploys the EC2 forensics engine.

The function subscribes to ``Endon Forensics Requested`` on the Endon bus and collects
evidence. Its role can inspect instances, snapshot volumes, read the console, look up
CloudTrail, run read-only SSM live-response commands, and write evidence to the Object
Lock bucket. It holds **no** destructive EC2 permission — it can never terminate, stop or
delete the instance, its volumes, or the snapshots it takes. The infrastructure test
enforces that.
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
from aws_cdk import aws_sqs as sqs
from constructs import Construct

from endon_forensics import rules
from lambda_bundle import stage_lambda_source
from platform_stack import PlatformStack

COMPONENT_ROOT = Path(__file__).resolve().parents[1]
REPO_ROOT = COMPONENT_ROOT.parent


def event_pattern(pattern: dict[str, Any]) -> events.EventPattern:
    return events.EventPattern(source=pattern["source"], detail_type=pattern["detail-type"])


class ForensicsStack(Stack):
    def __init__(
        self, scope: Construct, construct_id: str, *, platform: PlatformStack, **kwargs: Any
    ) -> None:
        super().__init__(scope, construct_id, **kwargs)

        dead_letters = sqs.Queue(
            self,
            "ForensicsDeadLetters",
            encryption=sqs.QueueEncryption.SQS_MANAGED,
            enforce_ssl=True,
            retention_period=Duration.days(14),
        )
        log_group = logs.LogGroup(
            self,
            "ForensicsLogs",
            retention=logs.RetentionDays.ONE_YEAR,
            encryption_key=platform.key,
        )

        self.function = lambda_.Function(
            self,
            "ForensicsEngine",
            description="Endon AI EC2 forensic evidence collection",
            runtime=lambda_.Runtime.PYTHON_3_13,
            architecture=lambda_.Architecture.ARM_64,
            handler="endon_forensics.handler.lambda_handler",
            code=lambda_.Code.from_asset(
                stage_lambda_source(
                    "forensics", REPO_ROOT / "endon-core" / "src", COMPONENT_ROOT / "src"
                )
            ),
            memory_size=512,
            timeout=Duration.minutes(10),
            tracing=lambda_.Tracing.ACTIVE,
            log_group=log_group,
            logging_format=lambda_.LoggingFormat.JSON,
            dead_letter_queue=dead_letters,
            retry_attempts=2,
            environment={
                "ENDON_EVENT_BUS": platform.bus.event_bus_name,
                "ENDON_EVIDENCE_BUCKET": platform.evidence_bucket.bucket_name,
                "ENDON_INCIDENTS_TABLE": platform.incidents_table.table_name,
            },
        )

        platform.bus.grant_put_events_to(self.function)
        platform.evidence_bucket.grant_read_write(self.function)
        platform.key.grant(self.function, "kms:Decrypt", "kms:GenerateDataKey*")
        for statement in self._collection_permissions():
            self.function.add_to_role_policy(statement)

        events.Rule(
            self,
            "ForensicsRequested",
            description="Collect evidence when the response engine isolates an instance",
            event_bus=platform.bus,
            event_pattern=event_pattern(rules.FORENSICS_REQUESTED),
            targets=[
                targets.LambdaFunction(
                    self.function,
                    dead_letter_queue=dead_letters,
                    retry_attempts=3,
                    max_event_age=Duration.hours(6),
                )
            ],
        )

        alarm_action = cloudwatch_actions.SnsAction(platform.alerts_topic)
        for alarm_id, metric, description in (
            (
                "ForensicsErrorsAlarm",
                self.function.metric_errors(period=Duration.minutes(5)),
                "The Endon forensics engine raised an unhandled error",
            ),
            (
                "ForensicsDeadLettersAlarm",
                dead_letters.metric_approximate_number_of_messages_visible(
                    period=Duration.minutes(5)
                ),
                "A forensics request could not be delivered — evidence may not have been collected",
            ),
        ):
            alarm = cloudwatch.Alarm(
                self,
                alarm_id,
                alarm_description=description,
                metric=metric,
                threshold=1,
                evaluation_periods=1,
                comparison_operator=cloudwatch.ComparisonOperator.GREATER_THAN_OR_EQUAL_TO_THRESHOLD,
                treat_missing_data=cloudwatch.TreatMissingData.NOT_BREACHING,
            )
            alarm.add_alarm_action(alarm_action)

    def _collection_permissions(self) -> list[iam.PolicyStatement]:
        partition, region, account = self.partition, self.region, self.account
        return [
            iam.PolicyStatement(
                sid="InspectInstances",
                actions=[
                    "ec2:DescribeInstances",
                    "ec2:DescribeInstanceAttribute",
                    "ec2:DescribeVolumes",
                    "ec2:DescribeSnapshots",
                    "ec2:DescribeSecurityGroups",
                    "ec2:GetConsoleOutput",
                    "ec2:GetConsoleScreenshot",
                    "autoscaling:DescribeAutoScalingInstances",
                ],
                resources=["*"],  # Describe/Get APIs do not support resource-level scoping
            ),
            iam.PolicyStatement(
                sid="SnapshotVolumesForEvidence",
                actions=["ec2:CreateSnapshot", "ec2:CreateSnapshots", "ec2:CreateTags"],
                resources=[
                    f"arn:{partition}:ec2:{region}:{account}:volume/*",
                    f"arn:{partition}:ec2:{region}:{account}:snapshot/*",
                    f"arn:{partition}:ec2:{region}:{account}:instance/*",
                ],
            ),
            iam.PolicyStatement(
                sid="ReadCloudTrail",
                actions=["cloudtrail:LookupEvents"],
                resources=["*"],  # LookupEvents does not support resource-level scoping
            ),
            iam.PolicyStatement(
                sid="LiveResponseReadOnly",
                actions=[
                    "ssm:DescribeInstanceInformation",
                    "ssm:SendCommand",
                    "ssm:GetCommandInvocation",
                ],
                resources=[
                    f"arn:{partition}:ec2:{region}:{account}:instance/*",
                    f"arn:{partition}:ssm:{region}:*:document/AWS-RunShellScript",
                    f"arn:{partition}:ssm:{region}:{account}:*",
                ],
            ),
            # Defense in depth: the forensics role must never be able to destroy the very
            # evidence (or the host) it exists to preserve.
            iam.PolicyStatement(
                sid="DenyDestructiveActions",
                effect=iam.Effect.DENY,
                actions=[
                    "ec2:TerminateInstances",
                    "ec2:StopInstances",
                    "ec2:DeleteSnapshot",
                    "ec2:DeleteVolume",
                    "ec2:DeregisterImage",
                    "s3:DeleteObject",
                    "s3:DeleteObjectVersion",
                    "s3:BypassGovernanceRetention",
                ],
                resources=["*"],
            ),
        ]
