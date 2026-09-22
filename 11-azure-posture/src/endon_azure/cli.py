"""Command line for the Azure posture scanner.

endon-azure scan resources.json --fail-on HIGH     # scan a Resource Graph export
endon-azure scan --live --subscription <id>        # pull live via Azure Resource Graph
"""

from __future__ import annotations

import argparse
import sys

from endon_azure import report
from endon_azure.resources import load, load_file
from endon_azure.scanner import scan
from endon_core.findings import Severity


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="endon-azure", description="Endon AI Azure posture scanner."
    )
    sub = parser.add_subparsers(dest="command", required=True)
    scan_cmd = sub.add_parser("scan", help="scan Azure resources for misconfigurations")
    scan_cmd.add_argument("path", nargs="?", help="a Resource Graph JSON export")
    scan_cmd.add_argument(
        "--live", action="store_true", help="collect live via Azure Resource Graph"
    )
    scan_cmd.add_argument(
        "--subscription", action="append", default=[], help="subscription id (repeatable)"
    )
    scan_cmd.add_argument(
        "--fail-on", choices=[s.value for s in Severity], default=Severity.HIGH.value
    )
    scan_cmd.add_argument("--json", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command != "scan":
        return 1

    if args.live:
        from endon_azure.collector import collect

        resources = load(collect(args.subscription))
    elif args.path:
        resources = load_file(args.path)
    else:
        print("Provide a JSON file or --live --subscription <id>.", file=sys.stderr)
        return 2

    result = report.evaluate_gate(scan(resources), Severity(args.fail_on))
    print(report.render_json(result) if args.json else report.render_console(result))
    if not result.passed:
        print(
            f"GATE FAILED: {result.blocking} finding(s) at or above {args.fail_on}.",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
