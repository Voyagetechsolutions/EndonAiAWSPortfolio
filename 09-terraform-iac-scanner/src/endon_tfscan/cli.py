"""Command line for the Terraform scanner — the pre-apply gate.

    terraform plan -out plan.out
    terraform show -json plan.out > plan.json
    endon-tfscan scan plan.json --fail-on HIGH        # exit 1 if any HIGH+ issue is planned

Run it in CI before `terraform apply` and an insecure change never reaches the account.
"""

from __future__ import annotations

import argparse
import sys

from endon_core.findings import Severity
from endon_tfscan import report
from endon_tfscan.plan import Plan
from endon_tfscan.scanner import scan


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="endon-tfscan", description="Endon AI Terraform IaC security scanner."
    )
    sub = parser.add_subparsers(dest="command", required=True)
    scan_cmd = sub.add_parser("scan", help="scan a `terraform show -json` plan document")
    scan_cmd.add_argument("plan", help="path to the plan JSON file")
    scan_cmd.add_argument(
        "--fail-on",
        choices=[s.value for s in Severity],
        default=Severity.HIGH.value,
        help="minimum severity that fails the gate (default HIGH)",
    )
    scan_cmd.add_argument("--json", action="store_true", help="emit JSON instead of a table")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command != "scan":
        return 1

    findings = scan(Plan.from_file(args.plan))
    result = report.evaluate_gate(findings, Severity(args.fail_on))

    if args.json:
        print(report.render_json(result))
    else:
        print(report.render_console(result))

    if not result.passed:
        print(
            f"GATE FAILED: {result.blocking} finding(s) at or above {args.fail_on}.",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
