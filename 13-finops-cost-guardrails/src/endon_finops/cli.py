"""Command line for the FinOps + security-cost analyzer.

endon-finops analyze costs.json                 # analyze a Cost Explorer / CUR export
endon-finops analyze costs.json --fail-on HIGH  # exit 1 on a security-cost anomaly
"""

from __future__ import annotations

import argparse
import sys

from endon_core.findings import Severity
from endon_finops import report
from endon_finops.engine import analyze_file


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="endon-finops", description="Endon AI FinOps + security-cost guardrails."
    )
    sub = parser.add_subparsers(dest="command", required=True)
    analyze = sub.add_parser("analyze", help="analyze a cost export for waste and cost anomalies")
    analyze.add_argument("path", help='a cost JSON export ({"rows": [...]} or a list)')
    analyze.add_argument(
        "--fail-on", choices=[s.value for s in Severity], default=Severity.HIGH.value
    )
    analyze.add_argument("--json", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command != "analyze":
        return 1

    result = report.evaluate(analyze_file(args.path), Severity(args.fail_on))
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
