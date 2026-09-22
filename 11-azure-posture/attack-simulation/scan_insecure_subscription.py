"""Scan the insecure Azure subscription fixture and print the gate result — offline.

    python 11-azure-posture/attack-simulation/scan_insecure_subscription.py

The same checks the tests assert against, run over the same fixture, so the demo and the proof
never drift. Writes the board to evidence/ for a screenshot.
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT / "endon-core" / "src"), str(ROOT / "11-azure-posture" / "src")]

from endon_azure import report  # noqa: E402
from endon_azure.resources import load_file  # noqa: E402
from endon_azure.scanner import scan  # noqa: E402
from endon_core.findings import Severity  # noqa: E402

FIXTURES = ROOT / "11-azure-posture" / "fixtures"
EVIDENCE = ROOT / "11-azure-posture" / "evidence"


def main() -> None:
    result = report.evaluate_gate(scan(load_file(FIXTURES / "insecure.json")), Severity.HIGH)
    board = report.render_console(result)
    print(board)

    EVIDENCE.mkdir(parents=True, exist_ok=True)
    (EVIDENCE / "azure-scan.txt").write_text(board + "\n", encoding="utf-8")

    clean = report.evaluate_gate(scan(load_file(FIXTURES / "secure.json")), Severity.HIGH)
    print(
        f"\nHardened subscription: {len(clean.findings)} finding(s) — gate "
        + ("PASSED" if clean.passed else "FAILED")
    )


if __name__ == "__main__":
    main()
