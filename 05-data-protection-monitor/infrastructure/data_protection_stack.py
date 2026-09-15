"""Deploys the data protection monitor: an event consumer and a scheduled secrets scanner.

Two Lambdas share the codebase:

* the **event consumer** reacts to Amazon Macie findings and AWS Health credential-exposure
  events, normalizing them into Endon findings on the bus;
* the **scanner** runs on a schedule, reading Lambda env vars, EC2 user data and Secrets
  Manager for exposed secrets.

Both roles are read-only across the services they inspect (they publish findings and write
reports, but never read a secret's *value* from Secrets Manager and never change a
resource). The infrastructure test enforces the read-only surface.
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

from endon_dataprotection import rules
from lambda_bundle import stage_lambda_source
from platform_stack import PlatformStack

COMPONENT_ROOT = Path(__file__).resolve().parents[1]
REPO_ROOT = COMPONENT_ROOT.parent

# Read-only inspection. Note: SecretsManager list only (never GetSecretValue) — the monitor
# must never read a secret's plaintext.
READ_ONLY_ACTIONS = [
    "lambda:ListFunctions",
    "lambda:GetFunctionConfiguration",
    "ec2:DescribeInstances",
    "ec2:DescribeInstanceAttribute",
    "secretsmanager:ListSecrets",
    "macie2:GetFindings",
    "macie2:ListFindings",
]


def event_pattern(pattern: dict[str, Any]) -> events.EventPattern:
    return events.EventPattern(
        source=pattern.get("source"),
        detail_type=pattern.get("detail-type"),
        detail=pattern.get("detail"),
    )


class DataProtectionStack(Stack):
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

        code = lambda_.Code.from_asset(
            stage_lambda_source(
                "data-protection", REPO_ROOT / "endon-core" / "src", COMPONENT_ROOT / "src"
            )
        )
        common_env = {
            "ENDON_EVENT_BUS": platform.bus.event_bus_name,
            "ENDON_EVIDENCE_BUCKET": platform.evidence_bucket.bucket_name,
        }

        self.event_consumer = self._function(
            "EventConsumer",
            "endon_dataprotection.handler.event_handler",
            code,
            platform,
            common_env,
            Duration.seconds(60),
        )
        self.scanner = self._function(
            "SecretsScanner",
            "endon_dataprotection.handler.scan_handler",
            code,
            platform,
            {**common_env, "ENDON_DP_PUBLIC_MIN_SEVERITY": "MEDIUM"},
            Duration.minutes(5),
        )

        platform.bus.grant_put_events_to(self.event_consumer)
        platform.bus.grant_put_events_to(self.scanner)
        platform.evidence_bucket.grant_put(self.scanner)
        platform.key.grant(self.scanner, "kms:Decrypt", "kms:GenerateDataKey*")
        self.scanner.add_to_role_policy(
            iam.PolicyStatement(
                sid="ReadOnlyInspection", actions=READ_ONLY_ACTIONS, resources=["*"]
            )
        )
        self.event_consumer.add_to_role_policy(
            iam.PolicyStatement(
                sid="ReadMacie",
                actions=["macie2:GetFindings", "macie2:ListFindings"],
                resources=["*"],
            )
        )

        for rule_id, pattern in (
            ("MacieFindings", rules.MACIE_FINDINGS),
            ("HealthCredentialsExposed", rules.HEALTH_CREDENTIALS_EXPOSED),
        ):
            events.Rule(
                self,
                rule_id,
                description=f"Route {rule_id} to the data-protection consumer",
                event_pattern=event_pattern(pattern),
                targets=[targets.LambdaFunction(self.event_consumer)],
            )

        events.Rule(
            self,
            "DailySecretsScan",
            description="Scan for exposed secrets on a schedule",
            schedule=schedule or events.Schedule.rate(Duration.hours(24)),
            targets=[targets.LambdaFunction(self.scanner)],
        )

        alarm_action = cloudwatch_actions.SnsAction(platform.alerts_topic)
        for fn, alarm_id in (
            (self.event_consumer, "EventConsumerErrors"),
            (self.scanner, "ScannerErrors"),
        ):
            alarm = cloudwatch.Alarm(
                self,
                alarm_id,
                alarm_description="The Endon data-protection monitor raised an error",
                metric=fn.metric_errors(period=Duration.minutes(5)),
                threshold=1,
                evaluation_periods=1,
                comparison_operator=cloudwatch.ComparisonOperator.GREATER_THAN_OR_EQUAL_TO_THRESHOLD,
                treat_missing_data=cloudwatch.TreatMissingData.NOT_BREACHING,
            )
            alarm.add_alarm_action(alarm_action)

    def _function(self, cid, handler, code, platform, environment, timeout) -> lambda_.Function:
        return lambda_.Function(
            self,
            cid,
            description=f"Endon AI data protection ({cid})",
            runtime=lambda_.Runtime.PYTHON_3_13,
            architecture=lambda_.Architecture.ARM_64,
            handler=handler,
            code=code,
            memory_size=512,
            timeout=timeout,
            tracing=lambda_.Tracing.ACTIVE,
            log_group=logs.LogGroup(
                self,
                f"{cid}Logs",
                retention=logs.RetentionDays.ONE_YEAR,
                encryption_key=platform.key,
            ),
            logging_format=lambda_.LoggingFormat.JSON,
            environment=environment,
        )
