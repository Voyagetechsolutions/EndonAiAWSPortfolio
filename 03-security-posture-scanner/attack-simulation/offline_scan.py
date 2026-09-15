"""Scan a deliberately vulnerable AWS environment offline and report the detection rate.

No AWS account is used - moto emulates S3, EC2, RDS, CloudTrail, KMS, IAM, GuardDuty and
Config. The environment and the manifest of expected findings come from the same testkit
the benchmark test asserts against, so the demo and the test can never drift apart.

    python 03-security-posture-scanner/attack-simulation/offline_scan.py
    python 03-security-posture-scanner/attack-simulation/offline_scan.py --html report.html
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [
    str(ROOT / "endon-core" / "src"),
    str(ROOT / "03-security-posture-scanner" / "src"),
    str(ROOT / "03-security-posture-scanner" / "tests"),
]

os.environ.update(
    {
        "AWS_ACCESS_KEY_ID": "offline",
        "AWS_SECRET_ACCESS_KEY": "offline",
        "AWS_SESSION_TOKEN": "offline",
        "AWS_DEFAULT_REGION": "us-east-1",
    }
)
os.environ.pop("AWS_PROFILE", None)

from moto import mock_aws  # noqa: E402

from endon_core.aws import ClientFactory  # noqa: E402
from endon_posture.reporting import render_console, render_html  # noqa: E402
from endon_posture.scanner import PostureScanner  # noqa: E402
from posture_testkit import REGION, build_vulnerable_environment  # noqa: E402


def detection_summary(manifest, result) -> str:
    expected = manifest.expected_control_ids
    found = result.control_ids
    detected = expected & found
    missed = sorted(expected - found)
    extra = sorted(found - expected)

    lines = ["", "DETECTION BENCHMARK", "-" * 19]
    lines.append(f"  Planted misconfigurations : {len(expected)} controls across 8 services")
    lines.append(
        f"  Detected                  : {len(detected)}/{len(expected)} ({len(detected) / len(expected):.0%})"
    )
    lines.append(f"  Missed                    : {', '.join(missed) if missed else 'none'}")
    lines.append(f"  Additional (baseline)     : {', '.join(extra) if extra else 'none'}")
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--html", type=Path, help="also write an HTML report to this path")
    args = parser.parse_args()

    with mock_aws():
        clients = ClientFactory(region=REGION)
        manifest = build_vulnerable_environment(clients)
        result = PostureScanner().scan_account(clients, region=REGION)

    print(render_console(result))
    print(detection_summary(manifest, result))

    if args.html:
        args.html.write_text(render_html(result), encoding="utf-8")
        print(f"\nWrote HTML report to {args.html}")


if __name__ == "__main__":
    main()
