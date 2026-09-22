"""Command line for the CloudTrail detection engine.

endon-siem detect trail.json                    # detect over a CloudTrail log file
endon-siem detect trail.json --alert-on HIGH    # exit 1 if any HIGH+ detection fires
endon-siem detect trail.json --json             # machine-readable detections
"""

from __future__ import annotations

import argparse
import sys

from endon_core.findings import Severity
from endon_siem import report
from endon_siem.engine import detect_file


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="endon-siem", description="Endon AI CloudTrail detection engine."
    )
    sub = parser.add_subparsers(dest="command", required=True)
    detect = sub.add_parser("detect", help="run detections over a CloudTrail log")
    detect.add_argument("path", help='a CloudTrail JSON file ({"Records": [...]} or a list)')
    detect.add_argument(
        "--alert-on", choices=[s.value for s in Severity], default=Severity.HIGH.value
    )
    detect.add_argument("--json", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command != "detect":
        return 1

    result = report.evaluate(detect_file(args.path), Severity(args.alert_on))
    print(report.render_json(result) if args.json else report.render_console(result))
    if not result.passed:
        print(
            f"ALERTS: {result.alerting} detection(s) at or above {args.alert_on}.", file=sys.stderr
        )
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
