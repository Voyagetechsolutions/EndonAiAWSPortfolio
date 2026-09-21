"""Standalone CDK app for the CI/CD OIDC trust.

Deployed once per account that GitHub Actions deploys into.

    cdk deploy -c github:owner=Voyagetechsolutions -c github:repo=EndonAiAWSPortfolio
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path[:0] = [
    str(HERE),
    str(HERE.parent / "src"),
    str(ROOT / "endon-core" / "src"),
    str(ROOT / "02-iam-security-analyzer" / "src"),
    str(ROOT / "03-security-posture-scanner" / "src"),
]

from aws_cdk import App, Environment, Tags  # noqa: E402

from pipeline_stack import PipelineStack  # noqa: E402


def main() -> None:
    app = App()
    PipelineStack(
        app,
        "EndonPipeline",
        github_owner=app.node.try_get_context("github:owner") or "Voyagetechsolutions",
        github_repo=app.node.try_get_context("github:repo") or "EndonAiAWSPortfolio",
        env=Environment(
            account=os.environ.get("CDK_DEFAULT_ACCOUNT"),
            region=os.environ.get("CDK_DEFAULT_REGION"),
        ),
    )
    Tags.of(app).add("project", "endon-ai")
    Tags.of(app).add("component", "cicd-pipeline")
    app.synth()


if __name__ == "__main__":
    main()
