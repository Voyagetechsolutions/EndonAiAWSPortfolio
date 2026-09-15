"""CDK entry point: deploys the Endon AI platform as one system.

cdk deploy --all                                          # response engine in dry-run
cdk deploy --all -c endon:responseMode=enforce            # automated containment on
cdk deploy --all -c endon:alertEmail=security@example.com
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
COMPONENT_PATHS = (
    "endon-core/src",
    "endon-core/infrastructure",
    "01-threat-detection-response/src",
    "01-threat-detection-response/infrastructure",
    "02-iam-security-analyzer/src",
    "02-iam-security-analyzer/infrastructure",
    "03-security-posture-scanner/src",
    "03-security-posture-scanner/infrastructure",
)
sys.path[:0] = [str(ROOT / path) for path in COMPONENT_PATHS]

from aws_cdk import App, Environment, Tags  # noqa: E402

from detection_stack import DetectionResponseStack  # noqa: E402
from iam_analyzer_stack import IamAnalyzerStack  # noqa: E402
from platform_stack import PlatformStack  # noqa: E402
from posture_scanner_stack import PostureScannerStack  # noqa: E402


def main() -> None:
    app = App()
    env = Environment(
        account=os.environ.get("CDK_DEFAULT_ACCOUNT"),
        region=os.environ.get("CDK_DEFAULT_REGION"),
    )

    platform = PlatformStack(
        app,
        "EndonPlatform",
        alert_email=app.node.try_get_context("endon:alertEmail") or None,
        env=env,
    )
    DetectionResponseStack(
        app,
        "EndonDetectionResponse",
        platform=platform,
        response_mode=app.node.try_get_context("endon:responseMode") or "dry_run",
        env=env,
    )
    IamAnalyzerStack(app, "EndonIamAnalyzer", platform=platform, env=env)
    PostureScannerStack(app, "EndonPostureScanner", platform=platform, env=env)

    Tags.of(app).add("project", "endon-ai")
    Tags.of(app).add("managed-by", "aws-cdk")
    app.synth()


if __name__ == "__main__":
    main()
