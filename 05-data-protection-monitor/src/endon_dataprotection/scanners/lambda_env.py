"""Scan Lambda function environment variables for secrets.

Environment variables are the most common place secrets get left in the open on AWS: they
are visible to anyone with `lambda:GetFunctionConfiguration` and are not encrypted at rest
beyond the default key unless a customer key is configured.
"""

from __future__ import annotations

from collections.abc import Iterator

from endon_core.findings import Finding, Resource
from endon_dataprotection.context import ScanContext
from endon_dataprotection.scanners.base import describe_matches, max_severity, scanner


@scanner("Lambda")
def lambda_environment(ctx: ScanContext) -> Iterator[Finding]:
    lambda_client = ctx.clients("lambda")
    for page in lambda_client.get_paginator("list_functions").paginate():
        for function in page.get("Functions", []):
            name = function["FunctionName"]
            variables = (function.get("Environment") or {}).get("Variables") or {}
            matches = ctx.secrets.scan_mapping(variables, location=f"lambda:{name}")
            if not matches:
                continue
            resource = Resource(
                "AwsLambdaFunction",
                function.get("FunctionArn", name),
                region=ctx.region,
                details={"functionName": name},
            )
            yield ctx.finding(
                finding_type="DataProtection:Lambda/SecretInEnvironment",
                title=f"Secret in Lambda environment variables: {name}",
                severity=max_severity(matches),
                resource=resource,
                description=(
                    f"Function '{name}' has {len(matches)} likely secret(s) in its environment "
                    f"variables. {describe_matches(matches)}"
                ),
                remediation=(
                    "Move secrets to AWS Secrets Manager or SSM Parameter Store (SecureString) and "
                    "fetch them at runtime; rotate any exposed secret immediately."
                ),
                control_id="DP-LAMBDA-001",
                tags={
                    "service": "Lambda",
                    "secretCount": str(len(matches)),
                    "kinds": ",".join(sorted({m.kind for m in matches})),
                },
            )
