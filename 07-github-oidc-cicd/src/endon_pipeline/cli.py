"""Pipeline command-line entry point, called by the GitHub Actions workflow.

endon-pipeline gate --iam --region us-east-1        # pre-deploy IAM analysis gate
endon-pipeline gate --posture --region us-east-1    # post-deploy posture gate
endon-pipeline simulate                             # OIDC trust + blast-radius proof
"""

from __future__ import annotations

import argparse
import json
import sys

import boto3

from endon_core.aws import ClientFactory
from endon_core.findings import Severity
from endon_pipeline import report
from endon_pipeline.gate import iam_gate, posture_gate


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="endon-pipeline", description="Endon AI secure CI/CD pipeline."
    )
    sub = parser.add_subparsers(dest="command", required=True)

    gate = sub.add_parser("gate", help="run a security gate and exit non-zero on blocking findings")
    which = gate.add_mutually_exclusive_group(required=True)
    which.add_argument("--iam", action="store_true", help="run the IAM analyzer gate (pre-deploy)")
    which.add_argument(
        "--posture", action="store_true", help="run the posture scanner gate (post-deploy)"
    )
    gate.add_argument("--region", default="us-east-1")
    gate.add_argument(
        "--fail-on", choices=[s.value for s in Severity], help="override the blocking severity"
    )

    sub.add_parser("simulate", help="print the OIDC trust and blast-radius proof")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "simulate":
        print(report.render_console())
        return 0
    if args.command == "gate":
        return _gate(args)
    return 1


def _gate(args: argparse.Namespace) -> int:
    clients = ClientFactory(region=args.region, session=boto3.session.Session())
    if args.iam:
        result = iam_gate(
            clients, args.region, Severity(args.fail_on) if args.fail_on else Severity.CRITICAL
        )
    else:
        result = posture_gate(
            clients, args.region, Severity(args.fail_on) if args.fail_on else Severity.HIGH
        )

    print(json.dumps(result.to_dict(), indent=2))
    if not result.passed:
        print(f"GATE FAILED: {result.summary}", file=sys.stderr)
        return 1
    print(f"GATE PASSED: {result.summary}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
