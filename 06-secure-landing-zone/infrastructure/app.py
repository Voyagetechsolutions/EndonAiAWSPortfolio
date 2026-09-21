"""Standalone CDK app for the landing zone.

Deployed in the organization *management* account (not the platform's workload account), so
it is a separate app from infrastructure/app.py.

    python build first is not needed. From this folder:
    cdk deploy -c endon:orgRootId=r-xxxx -c endon:organizationId=o-xxxxxxxxxx
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path[:0] = [str(HERE), str(HERE.parent / "src")]

from aws_cdk import App, Environment, Tags  # noqa: E402

from landing_zone_stack import LandingZoneStack  # noqa: E402


def main() -> None:
    app = App()
    LandingZoneStack(
        app,
        "EndonLandingZone",
        env=Environment(
            account=os.environ.get("CDK_DEFAULT_ACCOUNT"),
            region=os.environ.get("CDK_DEFAULT_REGION"),
        ),
    )
    Tags.of(app).add("project", "endon-ai")
    Tags.of(app).add("component", "landing-zone")
    app.synth()


if __name__ == "__main__":
    main()
