"""Deploys the SOC: a read-only web console over the platform's incident and finding tables.

The security shape of this stack is the point:

* the Lambda has **read-only** access to the two DynamoDB tables (get/query/scan, never put or
  delete) and read-only calls to the detective services for the health panel - a dashboard
  that cannot write cannot be turned into a weapon by whoever reaches it;
* every API route sits behind an **Amazon Cognito** authorizer, so nothing is served
  unauthenticated;
* the function decrypts table data with the platform KMS key but holds no other privilege.

The infrastructure test asserts the read-only surface and the Cognito gate.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from aws_cdk import Duration, Stack
from aws_cdk import aws_apigateway as apigateway
from aws_cdk import aws_cloudwatch as cloudwatch
from aws_cdk import aws_cloudwatch_actions as cloudwatch_actions
from aws_cdk import aws_cognito as cognito
from aws_cdk import aws_iam as iam
from aws_cdk import aws_lambda as lambda_
from aws_cdk import aws_logs as logs
from constructs import Construct

from lambda_bundle import stage_lambda_source
from platform_stack import PlatformStack

COMPONENT_ROOT = Path(__file__).resolve().parents[1]
REPO_ROOT = COMPONENT_ROOT.parent

# Read-only detective-control health probes for the dashboard's service panel.
HEALTH_READ_ACTIONS = [
    "guardduty:ListDetectors",
    "securityhub:DescribeHub",
    "cloudtrail:DescribeTrails",
    "cloudtrail:GetTrailStatus",
    "config:DescribeConfigurationRecorderStatus",
]


class SocStack(Stack):
    def __init__(
        self,
        scope: Construct,
        construct_id: str,
        *,
        platform: PlatformStack,
        **kwargs: Any,
    ) -> None:
        super().__init__(scope, construct_id, **kwargs)

        code = lambda_.Code.from_asset(
            stage_lambda_source("soc", REPO_ROOT / "endon-core" / "src", COMPONENT_ROOT / "src")
        )
        self.app_function = lambda_.Function(
            self,
            "SocApp",
            description="Endon AI Security Operations Center (read-only web console)",
            runtime=lambda_.Runtime.PYTHON_3_13,
            architecture=lambda_.Architecture.ARM_64,
            handler="endon_soc.lambda_handler.handler",
            code=code,
            memory_size=512,
            timeout=Duration.seconds(30),
            tracing=lambda_.Tracing.ACTIVE,
            log_group=logs.LogGroup(
                self,
                "SocAppLogs",
                retention=logs.RetentionDays.ONE_YEAR,
                encryption_key=platform.key,
            ),
            logging_format=lambda_.LoggingFormat.JSON,
            environment={
                "ENDON_INCIDENTS_TABLE": platform.incidents_table.table_name,
                "ENDON_FINDINGS_TABLE": platform.findings_table.table_name,
                "ENDON_REGION": self.region,
            },
        )

        # Read-only over the platform data (grant_read_data adds no write/delete actions).
        platform.incidents_table.grant_read_data(self.app_function)
        platform.findings_table.grant_read_data(self.app_function)
        platform.key.grant_decrypt(self.app_function)
        self.app_function.add_to_role_policy(
            iam.PolicyStatement(
                sid="DetectiveControlHealth", actions=HEALTH_READ_ACTIONS, resources=["*"]
            )
        )

        # Authentication: a Cognito user pool gates every route.
        self.user_pool = cognito.UserPool(
            self,
            "SocUserPool",
            self_sign_up_enabled=False,  # operators are invited, never self-registered
            sign_in_aliases=cognito.SignInAliases(email=True),
            password_policy=cognito.PasswordPolicy(
                min_length=12,
                require_lowercase=True,
                require_uppercase=True,
                require_digits=True,
                require_symbols=True,
            ),
            mfa=cognito.Mfa.REQUIRED,
            mfa_second_factor=cognito.MfaSecondFactor(otp=True, sms=False),
        )
        self.user_pool_client = self.user_pool.add_client(
            "SocWebClient",
            generate_secret=True,
            auth_flows=cognito.AuthFlow(user_srp=True),
        )
        authorizer = apigateway.CognitoUserPoolsAuthorizer(
            self, "SocAuthorizer", cognito_user_pools=[self.user_pool]
        )

        self.api = apigateway.LambdaRestApi(
            self,
            "SocApi",
            handler=self.app_function,
            proxy=True,
            cloud_watch_role=False,
            description="Endon AI SOC console (Cognito-gated, read-only)",
            deploy_options=apigateway.StageOptions(stage_name="soc"),
            default_method_options=apigateway.MethodOptions(
                authorization_type=apigateway.AuthorizationType.COGNITO,
                authorizer=authorizer,
            ),
        )

        alarm = cloudwatch.Alarm(
            self,
            "SocAppErrors",
            alarm_description="The Endon SOC application raised an error",
            metric=self.app_function.metric_errors(period=Duration.minutes(5)),
            threshold=1,
            evaluation_periods=1,
            comparison_operator=cloudwatch.ComparisonOperator.GREATER_THAN_OR_EQUAL_TO_THRESHOLD,
            treat_missing_data=cloudwatch.TreatMissingData.NOT_BREACHING,
        )
        alarm.add_alarm_action(cloudwatch_actions.SnsAction(platform.alerts_topic))
