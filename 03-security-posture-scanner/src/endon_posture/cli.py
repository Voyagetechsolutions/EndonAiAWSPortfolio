"""Command-line entry point for the posture scanner.

endon-posture-scanner scan --region us-east-1
endon-posture-scanner scan --region us-east-1 --formats console,html --output-dir reports/
endon-posture-scanner scan --region us-east-1 --fail-on HIGH
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

import boto3

from endon_core.aws import ClientFactory
from endon_core.findings import Severity
from endon_posture.reporting import RENDERERS
from endon_posture.scanner import PostureScanner

_EXTENSIONS = {"json": "json", "csv": "csv", "html": "html", "console": "txt"}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="endon-posture-scanner",
        description="Scan an AWS account/region for security misconfigurations.",
    )
    sub = parser.add_subparsers(dest="command", required=True)
    scan = sub.add_parser("scan", help="scan an account/region and report")
    scan.add_argument("--region", default="us-east-1")
    scan.add_argument("--profile", help="AWS named profile to use")
    scan.add_argument(
        "--formats", default="console", help="comma-separated: console, json, csv, html"
    )
    scan.add_argument("--output-dir", type=Path, help="write each format to this directory")
    scan.add_argument("--output", type=Path, help="write a single format to this file")
    scan.add_argument(
        "--fail-on",
        choices=[s.value for s in Severity],
        help="exit non-zero if any finding is at or above this severity (for CI gating)",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "scan":
        return _scan(args)
    return 1


def _scan(args: argparse.Namespace) -> int:
    session = boto3.session.Session(profile_name=args.profile) if args.profile else None
    clients = ClientFactory(region=args.region, session=session)
    result = PostureScanner().scan_account(clients, region=args.region)

    formats = [f.strip() for f in args.formats.split(",") if f.strip()]
    unknown = [f for f in formats if f not in RENDERERS]
    if unknown:
        print(f"Unknown format(s): {', '.join(unknown)}", file=sys.stderr)
        return 2

    for fmt in formats:
        content = RENDERERS[fmt](result)
        destination = _destination(args, fmt, len(formats))
        if destination is None:
            print(content)
        else:
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_text(content, encoding="utf-8")
            print(f"Wrote {fmt} report to {destination}", file=sys.stderr)

    if args.fail_on and any(f.severity.at_least(Severity(args.fail_on)) for f in result.findings):
        print(f"Findings at or above {args.fail_on} were detected.", file=sys.stderr)
        return 1
    return 0


def _destination(args: argparse.Namespace, fmt: str, format_count: int) -> Path | None:
    if args.output and format_count == 1:
        return args.output
    if args.output_dir:
        return args.output_dir / f"posture-assessment.{_EXTENSIONS[fmt]}"
    return None


if __name__ == "__main__":
    raise SystemExit(main())
