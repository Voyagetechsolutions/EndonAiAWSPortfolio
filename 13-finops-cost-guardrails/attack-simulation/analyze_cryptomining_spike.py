"""Analyze a cost export where a compromise shows up on the bill — offline.

    python 13-finops-cost-guardrails/attack-simulation/analyze_cryptomining_spike.py

The anomalous export contains a cryptomining compute spike and a data-egress spike alongside
ordinary waste. The same analyzers the tests assert against run over it, so the demo and the
proof never drift. Writes the board to evidence/ for a screenshot.
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT / "endon-core" / "src"), str(ROOT / "13-finops-cost-guardrails" / "src")]

from endon_core.findings import Severity  # noqa: E402
from endon_finops import report  # noqa: E402
from endon_finops.engine import analyze_file  # noqa: E402

FIXTURES = ROOT / "13-finops-cost-guardrails" / "fixtures"
EVIDENCE = ROOT / "13-finops-cost-guardrails" / "evidence"


def main() -> None:
    result = report.evaluate(analyze_file(FIXTURES / "anomalous.json"), Severity.HIGH)
    board = report.render_console(result)
    print(board)

    EVIDENCE.mkdir(parents=True, exist_ok=True)
    (EVIDENCE / "cost-guardrails.txt").write_text(board + "\n", encoding="utf-8")

    clean = report.evaluate(analyze_file(FIXTURES / "clean.json"), Severity.HIGH)
    print(
        f"\nSteady-state bill: {len(clean.findings)} finding(s) — gate "
        + ("PASSED" if clean.passed else "FAILED")
    )


if __name__ == "__main__":
    main()
