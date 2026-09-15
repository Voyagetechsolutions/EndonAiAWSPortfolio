"""Standalone CDK app for hosting the portfolio site.

This is separate from the Endon platform app: the website is not part of the security
runtime, so it deploys on its own.

    python build.py                 # from portfolio-site/, first
    cdk deploy                      # CloudFront URL only
    cdk deploy -c domain=endonai.com -c hostedZoneId=Z... -c certArn=arn:aws:acm:us-east-1:...
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from aws_cdk import App, Environment, Tags  # noqa: E402
from site_stack import PortfolioSiteStack  # noqa: E402


def main() -> None:
    app = App()
    PortfolioSiteStack(
        app,
        "EndonPortfolioSite",
        domain=app.node.try_get_context("domain") or None,
        hosted_zone_id=app.node.try_get_context("hostedZoneId") or None,
        certificate_arn=app.node.try_get_context("certArn") or None,
        env=Environment(
            account=os.environ.get("CDK_DEFAULT_ACCOUNT"),
            region=os.environ.get("CDK_DEFAULT_REGION"),
        ),
    )
    Tags.of(app).add("project", "endon-ai")
    Tags.of(app).add("component", "portfolio-site")
    app.synth()


if __name__ == "__main__":
    main()
