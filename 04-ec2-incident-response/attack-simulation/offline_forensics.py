"""Replay an automatic forensic collection against an emulated, isolated instance.

Everything runs locally. moto emulates EC2, S3 (with Object Lock), SSM and CloudTrail.
An instance is put into the state Project 1 leaves a compromised host in — isolated in
the quarantine security group, termination protection on — and the forensics engine then
collects evidence in order of volatility, hashes it, and writes an immutable chain-of-
custody manifest. No real AWS account is touched.

    python 04-ec2-incident-response/attack-simulation/offline_forensics.py
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [
    str(ROOT / "endon-core" / "src"),
    str(ROOT / "01-threat-detection-response" / "src"),
    str(ROOT / "04-ec2-incident-response" / "src"),
    str(ROOT / "04-ec2-incident-response" / "tests"),
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
from endon_core.config import Settings  # noqa: E402
from endon_core.events import InMemoryEventBus  # noqa: E402
from endon_core.timeutil import parse_timestamp  # noqa: E402
from endon_forensics.engine import ForensicsEngine  # noqa: E402
from endon_forensics.evidence_store import EvidenceStore  # noqa: E402
from forensics_testkit import (  # noqa: E402
    EVIDENCE_BUCKET,
    REGION,
    create_evidence_bucket,
    forensics_request,
    isolated_instance,
)


def heading(text: str) -> None:
    print(f"\n{text}\n{'-' * len(text)}")


def main() -> None:
    with mock_aws():
        aws = ClientFactory(region=REGION)
        create_evidence_bucket(aws)
        instance = isolated_instance(aws)

        print("ENDON AI - OFFLINE FORENSIC COLLECTION")
        print(f"Isolated instance {instance['instance_id']} in the {REGION} lab (emulated AWS).")

        bus = InMemoryEventBus(account_id="123456789012", region=REGION)
        engine = ForensicsEngine(
            settings=Settings(region=REGION, evidence_bucket=EVIDENCE_BUCKET),
            clients=aws,
            store=EvidenceStore(EVIDENCE_BUCKET, aws("s3")),
            publisher=bus,
        )

        case = engine.collect(forensics_request(instance)["detail"])

        heading("COLLECTION TIMELINE")
        start = parse_timestamp(case.opened_at)
        for entry in case.timeline:
            offset = (parse_timestamp(entry.at) - start).total_seconds()
            detail = f" - {entry.detail}" if entry.detail else ""
            print(f"  +{offset:6.3f}s  {entry.event}{detail}")

        heading("ISOLATION")
        for key, value in case.isolation.items():
            print(f"  {key}: {value}")

        heading("EVIDENCE COLLECTED (order of volatility)")
        width = max(len(e.id) for e in case.evidence)
        for e in case.evidence:
            sha = f"sha256:{e.sha256[:16]}…" if e.sha256 else "-"
            print(f"  [{e.status:<9}] {e.id:<{width}}  {sha}")
            if e.status.value != "COLLECTED" and e.detail.get("reason"):
                print(f"              reason: {e.detail['reason']}")

        heading("CHAIN OF CUSTODY")
        print(f"  Case status     : {case.status}")
        print(f"  Collector       : {case.collector_identity}")
        print(f"  EBS snapshots   : {', '.join(case.snapshot_ids) or 'none'}")
        print(f"  Manifest        : s3://{EVIDENCE_BUCKET}/{case.manifest_key}")
        print(f"  Manifest sha256 : {case.manifest_sha256}")

        # Prove the manifest is stored immutably (Object Lock) and matches.
        obj = aws("s3").get_object(Bucket=EVIDENCE_BUCKET, Key=case.manifest_key)
        stored = json.loads(obj["Body"].read())
        print(
            f"  Object Lock     : {obj.get('ObjectLockMode')} until {obj.get('ObjectLockRetainUntilDate')}"
        )
        print(f"  Evidence items in manifest: {len(stored['evidence'])}")


if __name__ == "__main__":
    main()
