"""Generate GuardDuty sample findings to exercise the deployed pipeline end to end.

Sample findings travel through EventBridge exactly like real ones. Endon always
handles them in dry-run, so no resource is changed even when the engine is in
enforce mode - this is the safe first test after `cdk deploy`.

    python generate_sample_findings.py --region us-east-1
    python generate_sample_findings.py --region us-east-1 --type Backdoor:EC2/C&CActivity.B
"""

from __future__ import annotations

import argparse
import sys

import boto3

DEFAULT_TYPES = [
    "UnauthorizedAccess:IAMUser/MaliciousIPCaller.Custom",
    "UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS",
    "Stealth:IAMUser/CloudTrailLoggingDisabled",
    "CryptoCurrency:EC2/BitcoinTool.B!DNS",
    "Policy:S3/BucketBlockPublicAccessDisabled",
    "Recon:EC2/PortProbeUnprotectedPort",
]


def main() -> None:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--region", required=True)
    parser.add_argument("--type", action="append", dest="types", help="finding type (repeatable)")
    args = parser.parse_args()

    guardduty = boto3.client("guardduty", region_name=args.region)
    detectors = guardduty.list_detectors()["DetectorIds"]
    if not detectors:
        sys.exit(
            f"GuardDuty is not enabled in {args.region}. Enable it first (Project 6 does this org-wide)."
        )

    finding_types = args.types or DEFAULT_TYPES
    guardduty.create_sample_findings(DetectorId=detectors[0], FindingTypes=finding_types)
    print(f"Requested {len(finding_types)} sample finding(s) from detector {detectors[0]}:")
    for finding_type in finding_types:
        print(f"  - {finding_type}")
    print(
        "\nFindings reach EventBridge within a few minutes. Check the incidents table and the alerts topic."
    )


if __name__ == "__main__":
    main()
