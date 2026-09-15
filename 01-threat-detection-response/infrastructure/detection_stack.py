"""Deploys the automated threat detection and response engine."""

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

from endon_detection import rules
from lambda_bundle import stage_lambda_source
from platform_stack import PlatformStack

COMPONENT_ROOT = Path(__file__).resolve().parents[1]
REPO_ROOT = COMPONENT_ROOT.parent
RESPONSE_MODES = ("dry_run", "enforce")


def event_pattern(pattern: dict[str, Any]) -> events.EventPattern:
    return events.EventPattern(
        source=pattern.get("source"),
        detail_type=pattern.get("detail-type"),
        detail=pattern.get("detail"),
    )


class DetectionResponseStack(Stack):
    def __init__(
        self,
        scope: Construct,
        construct_id: str,
        *,
        platform: PlatformStack,
        response_mode: str = "dry_run",
        **kwargs: Any,
    ) -> None:
        if response_mode not in RESPONSE_MODES:
            raise ValueError(
                f"response_mode must be one of {RESPONSE_MODES}, got {response_mode!r}"
            )
        super().__init__(scope, construct_id, **kwargs)

        dead_letters = sqs.Queue(
            self,
            "ResponseDeadLetters",
            encryption=sqs.QueueEncryption.SQS_MANAGED,
            enforce_ssl=True,
            retention_period=Duration.days(14),
        )
        log_group = logs.LogGroup(
            self,
            "ResponseEngineLogs",
            retention=logs.RetentionDays.ONE_YEAR,
            encryption_key=platform.key,
        )

        self.function = lambda_.Function(
            self,
            "ResponseEngine",
            description="Endon AI automated threat response engine",
            runtime=lambda_.Runtime.PYTHON_3_13,
            architecture=lambda_.Architecture.ARM_64,
            handler="endon_detection.handler.lambda_handler",
            code=lambda_.Code.from_asset(
                stage_lambda_source(
                    "detection-response", REPO_ROOT / "endon-core" / "src", COMPONENT_ROOT / "src"
                )
            ),
            memory_size=512,
            timeout=Duration.seconds(120),
            tracing=lambda_.Tracing.ACTIVE,
            log_group=log_group,
            logging_format=lambda_.LoggingFormat.JSON,
            dead_letter_queue=dead_letters,
            retry_attempts=2,
            environment={
                "ENDON_RESPONSE_MODE": response_mode,
                "ENDON_EVENT_BUS": platform.bus.event_bus_name,
                "ENDON_INCIDENTS_TABLE": platform.incidents_table.table_name,
                "ENDON_FINDINGS_TABLE": platform.findings_table.table_name,
                "ENDON_ALERTS_TOPIC_ARN": platform.alerts_topic.topic_arn,
                "ENDON_EVIDENCE_BUCKET": platform.evidence_bucket.bucket_name,
                "ENDON_PROTECTED_TAG": "endon:protected",
            },
        )

        platform.incidents_table.grant_read_write_data(self.function)
        platform.bus.grant_put_events_to(self.function)
        platform.alerts_topic.grant_publish(self.function)
        platform.key.grant(self.function, "kms:Decrypt", "kms:GenerateDataKey*")
        for statement in self._response_permissions():
            self.function.add_to_role_policy(statement)

        for rule_id, description, pattern, bus in (
            (
                "GuardDutyFindings",
                "GuardDuty findings to the response engine",
                rules.GUARDDUTY_FINDINGS,
                None,
            ),
            (
                "SecurityHubFindings",
                "High and critical Security Hub findings",
                rules.SECURITY_HUB_FINDINGS,
                None,
            ),
            (
                "EndonFindings",
                "Findings from Endon scanners and analyzers",
                rules.ENDON_FINDINGS,
                platform.bus,
            ),
        ):
            events.Rule(
                self,
                rule_id,
                description=description,
                event_bus=bus,
                event_pattern=event_pattern(pattern),
                targets=[
                    targets.LambdaFunction(
                        self.function,
                        dead_letter_queue=dead_letters,
                        retry_attempts=4,
                        max_event_age=Duration.hours(6),
                    )
                ],
            )

        # A responder that fails silently is worse than none: alert on errors and dead letters.
        alarm_action = cloudwatch_actions.SnsAction(platform.alerts_topic)
        for alarm_id, metric, description in (
            (
                "ResponseEngineErrorsAlarm",
                self.function.metric_errors(period=Duration.minutes(5)),
                "The Endon response engine raised an unhandled error",
            ),
            (
                "ResponseDeadLettersAlarm",
                dead_letters.metric_approximate_number_of_messages_visible(
                    period=Duration.minutes(5)
                ),
                "Security events could not be delivered to the Endon response engine",
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

    def _response_permissions(self) -> list[iam.PolicyStatement]:
        partition, region, account = self.partition, self.region, self.account
        return [
            iam.PolicyStatement(
                sid="ContainIamUsers",
                actions=[
                    "iam:ListAccessKeys",
                    "iam:UpdateAccessKey",
                    "iam:PutUserPolicy",
                    "iam:TagUser",
                    "iam:ListUserTags",
                ],
                resources=[f"arn:{partition}:iam::{account}:user/*"],
            ),
            iam.PolicyStatement(
                sid="ContainIamRoles",
                actions=["iam:GetRole", "iam:ListRoleTags", "iam:PutRolePolicy", "iam:TagRole"],
                resources=[f"arn:{partition}:iam::{account}:role/*"],
            ),
            iam.PolicyStatement(
                sid="InspectResources",
                actions=[
                    "ec2:DescribeInstances",
                    "ec2:DescribeSecurityGroups",
                    "autoscaling:DescribeAutoScalingInstances",
                    "cloudtrail:DescribeTrails",
                ],
                resources=[
                    "*"
                ],  # these List/Describe APIs do not support resource-level permissions
            ),
            iam.PolicyStatement(
                sid="IsolateEc2Instances",
                actions=[
                    "ec2:CreateSecurityGroup",
                    "ec2:AuthorizeSecurityGroupIngress",
                    "ec2:RevokeSecurityGroupIngress",
                    "ec2:RevokeSecurityGroupEgress",
                    "ec2:ModifyNetworkInterfaceAttribute",
                    "ec2:ModifyInstanceAttribute",
                    "ec2:CreateTags",
                ],
                resources=[f"arn:{partition}:ec2:{region}:{account}:*"],
            ),
            iam.PolicyStatement(
                sid="DetachFromAutoScaling",
                actions=["autoscaling:DetachInstances"],
                resources=[
                    f"arn:{partition}:autoscaling:{region}:{account}:autoScalingGroup:*:autoScalingGroupName/*"
                ],
            ),
            iam.PolicyStatement(
                sid="BlockS3PublicAccess",
                actions=[
                    "s3:PutBucketPublicAccessBlock",
                    "s3:GetBucketTagging",
                    "s3:PutBucketTagging",
                ],
                resources=[f"arn:{partition}:s3:::*"],
            ),
            iam.PolicyStatement(
                sid="RestoreCloudTrailLogging",
                actions=["cloudtrail:GetTrailStatus", "cloudtrail:StartLogging"],
                resources=[f"arn:{partition}:cloudtrail:{region}:{account}:trail/*"],
            ),
            # The responder can write IAM policies, so it must never be able to write them
            # on itself - otherwise compromising the function means owning the account.
            iam.PolicyStatement(
                sid="DenySelfModification",
                effect=iam.Effect.DENY,
                actions=[
                    "iam:PutRolePolicy",
                    "iam:DeleteRolePolicy",
                    "iam:AttachRolePolicy",
                    "iam:DetachRolePolicy",
                    "iam:TagRole",
                    "iam:UntagRole",
                    "iam:UpdateAssumeRolePolicy",
                    "iam:PutRolePermissionsBoundary",
                    "iam:DeleteRolePermissionsBoundary",
                ],
                resources=[self.function.role.role_arn],
            ),
            iam.PolicyStatement(
                sid="DenyAwsManagedRoles",
                effect=iam.Effect.DENY,
                actions=["iam:PutRolePolicy", "iam:TagRole"],
                resources=[
                    f"arn:{partition}:iam::{account}:role/aws-service-role/*",
                    f"arn:{partition}:iam::{account}:role/aws-reserved/*",
                ],
            ),
        ]
