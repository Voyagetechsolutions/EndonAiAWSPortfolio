"""Scan a deliberately leaky account offline and show the redacted findings.

No AWS account is used — moto emulates Lambda, EC2 and Secrets Manager. Secrets are
planted where they get left in real life (a Lambda's environment, an EC2 instance's user
data, an unrotated secret), then the monitor finds them and reports them fully redacted.
A Macie-style event is also replayed to show the sensitive-data classification path.

    python 05-data-protection-monitor/attack-simulation/offline_scan.py
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [
    str(ROOT / "endon-core" / "src"),
    str(ROOT / "05-data-protection-monitor" / "src"),
    str(ROOT / "05-data-protection-monitor" / "tests"),
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

from dataprotection_testkit import (  # noqa: E402
    RAW_SECRETS,
    REGION,
    build_leaky_account,
    macie_event,
)
from endon_core.aws import ClientFactory  # noqa: E402
from endon_dataprotection.normalizers import normalize_event  # noqa: E402
from endon_dataprotection.reporting import render_console  # noqa: E402
from endon_dataprotection.scanner import DataProtectionScanner  # noqa: E402


def main() -> None:
    with mock_aws():
        aws = ClientFactory(region=REGION)
        build_leaky_account(aws)
        result = DataProtectionScanner().scan_account(aws, region=REGION)

    print(render_console(result))

    print("\nMACIE CLASSIFICATION PATH")
    print("-" * 25)
    [public] = normalize_event(
        macie_event("customer-exports", public=True, categories=["PERSONAL_INFORMATION"])
    )
    print(f"  {public.severity}  {public.type}")
    print("    -> routes to Project 1 s3-public-exposure (auto Block Public Access)")

    print("\nREDACTION CHECK")
    print("-" * 15)
    blob = render_console(result)
    leaked = [s for s in RAW_SECRETS if s in blob]
    print(f"  Raw secrets in the report: {len(leaked)} (must be 0)")
    if leaked:
        raise SystemExit("FAILED: a raw secret appeared in the report")
    print("  All secret values are redacted to edge characters + a sha256 fingerprint.")


if __name__ == "__main__":
    main()
