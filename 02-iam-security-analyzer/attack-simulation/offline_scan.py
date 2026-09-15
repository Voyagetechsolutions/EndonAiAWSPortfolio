"""Scan a deliberately vulnerable IAM account offline and print the assessment.

No AWS account is used. The vulnerable account is the same fixture the tests assert
against (`tests/iam_testkit.py`): every issue the analyzer detects is planted once,
alongside a few correctly configured principals to show it does not cry wolf.

    python 02-iam-security-analyzer/attack-simulation/offline_scan.py
    python 02-iam-security-analyzer/attack-simulation/offline_scan.py --html report.html
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [
    str(ROOT / "endon-core" / "src"),
    str(ROOT / "02-iam-security-analyzer" / "src"),
    str(ROOT / "02-iam-security-analyzer" / "tests"),
]

from endon_iam_analyzer.analyzer import IamAnalyzer  # noqa: E402
from endon_iam_analyzer.escalation import analyze as analyze_escalation  # noqa: E402
from endon_iam_analyzer.reporting import render_console, render_html  # noqa: E402
from iam_testkit import NOW, vulnerable_snapshot  # noqa: E402


def show_escalation_paths(snapshot) -> None:
    print("\nPRIVILEGE-ESCALATION PATHS")
    print("-" * 26)
    for result in analyze_escalation(snapshot).values():
        principal = result.principal
        if result.direct:
            techniques = ", ".join(f"{m.technique.id}" for m in result.direct)
            print(f"  {principal.kind} {principal.name}: direct via {techniques}")
        for reachable in result.via_roles.values():
            path = " -> ".join(reachable.path)
            techniques = ", ".join(m.technique.id for m in reachable.matches)
            print(f"  {principal.kind} {principal.name}: {path} then {techniques}")


def main() -> None:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--html", type=Path, help="also write an HTML report to this path")
    args = parser.parse_args()

    snapshot = vulnerable_snapshot()
    result = IamAnalyzer().analyze(snapshot, now=NOW)

    print(render_console(result))
    show_escalation_paths(snapshot)

    if args.html:
        args.html.write_text(render_html(result), encoding="utf-8")
        print(f"\nWrote HTML report to {args.html}")


if __name__ == "__main__":
    main()
