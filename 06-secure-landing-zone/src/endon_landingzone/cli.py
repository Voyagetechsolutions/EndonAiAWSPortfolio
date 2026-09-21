"""Command-line entry point: show the landing-zone structure and the guardrail proof.

endon-landing-zone report
endon-landing-zone report --format json
"""

from __future__ import annotations

import argparse

from endon_landingzone import report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="endon-landing-zone",
        description="Secure multi-account landing zone: structure and guardrail proof.",
    )
    sub = parser.add_subparsers(dest="command", required=True)
    show = sub.add_parser("report", help="show the OU tree, baseline and guardrail simulation")
    show.add_argument("--format", choices=["console", "json"], default="console")
    args = parser.parse_args(argv)

    if args.command == "report":
        print(report.render_json() if args.format == "json" else report.render_console())
        return 0
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
