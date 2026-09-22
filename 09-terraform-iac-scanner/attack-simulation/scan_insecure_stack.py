"""Scan the deliberately-insecure Terraform plan and print the gate result — offline.

    python 09-terraform-iac-scanner/attack-simulation/scan_insecure_stack.py

The same engine the tests assert against, run against the same plan fixture, so the demo and
the proof never drift. Writes the board to evidence/ for a screenshot.
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [
    str(ROOT / "endon-core" / "src"),
    str(ROOT / "02-iam-security-analyzer" / "src"),
    str(ROOT / "09-terraform-iac-scanner" / "src"),
]

from endon_core.findings import Severity  # noqa: E402
from endon_tfscan import report  # noqa: E402
from endon_tfscan.plan import Plan  # noqa: E402
from endon_tfscan.scanner import scan  # noqa: E402

PLANS = ROOT / "09-terraform-iac-scanner" / "terraform" / "plans"
EVIDENCE = ROOT / "09-terraform-iac-scanner" / "evidence"


def main() -> None:
    findings = scan(Plan.from_file(PLANS / "insecure.plan.json"))
    result = report.evaluate_gate(findings, fail_on=Severity.HIGH)
    board = report.render_console(result)
    print(board)

    EVIDENCE.mkdir(parents=True, exist_ok=True)
    (EVIDENCE / "scan-insecure.txt").write_text(board + "\n", encoding="utf-8")

    # And prove it stays quiet on the hardened plan.
    clean = report.evaluate_gate(scan(Plan.from_file(PLANS / "secure.plan.json")), Severity.HIGH)
    print(
        f"\nHardened plan: {len(clean.findings)} finding(s) — gate "
        + ("PASSED" if clean.passed else "FAILED")
    )


if __name__ == "__main__":
    main()
