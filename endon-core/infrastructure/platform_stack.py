"""Shared platform resources that every Endon component plugs into.

* one customer-managed KMS key for incident data, alerts, logs and evidence
* the Endon security event bus, with a 90-day archive for replaying incidents
* DynamoDB tables for incidents and findings
* the SNS alerts topic
* an Object Lock evidence bucket, so collected evidence cannot be altered or deleted
"""

from __future__ import annotations

from typing import Any

from aws_cdk import CfnOutput, Duration, RemovalPolicy, Stack
from aws_cdk import aws_dynamodb as dynamodb
from aws_cdk import aws_events as events
from aws_cdk import aws_iam as iam
from aws_cdk import aws_kms as kms
from aws_cdk import aws_s3 as s3
from aws_cdk import aws_sns as sns
from aws_cdk import aws_sns_subscriptions as subscriptions
from constructs import Construct

from endon_core.events import DEFAULT_BUS_NAME


class PlatformStack(Stack):
    def __init__(
        self, scope: Construct, construct_id: str, *, alert_email: str | None = None, **kwargs: Any
    ) -> None:
        super().__init__(scope, construct_id, **kwargs)

        self.key = kms.Key(
            self,
            "PlatformKey",
            alias="alias/endon-platform",
            description="Encrypts Endon AI incidents, findings, alerts, logs and evidence",
            enable_key_rotation=True,
            removal_policy=RemovalPolicy.RETAIN,
        )
        self.key.add_to_resource_policy(
            iam.PolicyStatement(
                sid="AllowCloudWatchLogsEncryption",
                principals=[iam.ServicePrincipal(f"logs.{self.region}.amazonaws.com")],
                actions=[
                    "kms:Encrypt*",
                    "kms:Decrypt*",
                    "kms:ReEncrypt*",
                    "kms:GenerateDataKey*",
                    "kms:Describe*",
                ],
                resources=["*"],
                conditions={
                    "ArnLike": {
                        "kms:EncryptionContext:aws:logs:arn": f"arn:{self.partition}:logs:{self.region}:{self.account}:log-group:*"
                    }
                },
            )
        )
        self.key.add_to_resource_policy(
            iam.PolicyStatement(
                sid="AllowCloudWatchAlarmsToPublishAlerts",
                principals=[iam.ServicePrincipal("cloudwatch.amazonaws.com")],
                actions=["kms:Decrypt", "kms:GenerateDataKey*"],
                resources=["*"],
                conditions={"StringEquals": {"aws:SourceAccount": self.account}},
            )
        )

        self.bus = events.EventBus(self, "SecurityBus", event_bus_name=DEFAULT_BUS_NAME)
        self.bus.archive(
            "SecurityBusArchive",
            archive_name="endon-security-events",
            description="Replay security events when re-investigating an incident",
            event_pattern=events.EventPattern(account=[self.account]),
            retention=Duration.days(90),
        )

        self.incidents_table = self._table("IncidentsTable", "incident_id")
        self.findings_table = self._table("FindingsTable", "finding_id")

        self.alerts_topic = sns.Topic(
            self,
            "AlertsTopic",
            display_name="Endon AI security alerts",
            master_key=self.key,
            enforce_ssl=True,
        )
        if alert_email:
            self.alerts_topic.add_subscription(subscriptions.EmailSubscription(alert_email))

        access_logs = s3.Bucket(
            self,
            "EvidenceAccessLogs",
            encryption=s3.BucketEncryption.S3_MANAGED,
            block_public_access=s3.BlockPublicAccess.BLOCK_ALL,
            enforce_ssl=True,
            removal_policy=RemovalPolicy.RETAIN,
            lifecycle_rules=[s3.LifecycleRule(expiration=Duration.days(400))],
        )
        self.evidence_bucket = s3.Bucket(
            self,
            "EvidenceBucket",
            encryption=s3.BucketEncryption.KMS,
            encryption_key=self.key,
            bucket_key_enabled=True,
            block_public_access=s3.BlockPublicAccess.BLOCK_ALL,
            enforce_ssl=True,
            minimum_tls_version=1.2,
            versioned=True,
            # Governance mode: evidence is immutable for 90 days for everyone except
            # principals explicitly granted s3:BypassGovernanceRetention.
            object_lock_enabled=True,
            object_lock_default_retention=s3.ObjectLockRetention.governance(Duration.days(90)),
            server_access_logs_bucket=access_logs,
            server_access_logs_prefix="evidence/",
            lifecycle_rules=[
                s3.LifecycleRule(
                    transitions=[
                        s3.Transition(
                            storage_class=s3.StorageClass.GLACIER_INSTANT_RETRIEVAL,
                            transition_after=Duration.days(30),
                        )
                    ]
                )
            ],
            removal_policy=RemovalPolicy.RETAIN,
        )

        for output_id, value in (
            ("EventBusName", self.bus.event_bus_name),
            ("IncidentsTableName", self.incidents_table.table_name),
            ("FindingsTableName", self.findings_table.table_name),
            ("AlertsTopicArn", self.alerts_topic.topic_arn),
            ("EvidenceBucketName", self.evidence_bucket.bucket_name),
        ):
            CfnOutput(self, output_id, value=value)

    def _table(self, construct_id: str, partition_key: str) -> dynamodb.Table:
        return dynamodb.Table(
            self,
            construct_id,
            partition_key=dynamodb.Attribute(
                name=partition_key, type=dynamodb.AttributeType.STRING
            ),
            billing_mode=dynamodb.BillingMode.PAY_PER_REQUEST,
            encryption=dynamodb.TableEncryption.CUSTOMER_MANAGED,
            encryption_key=self.key,
            point_in_time_recovery_specification=dynamodb.PointInTimeRecoverySpecification(
                point_in_time_recovery_enabled=True
            ),
            deletion_protection=True,
            removal_policy=RemovalPolicy.RETAIN,
        )
