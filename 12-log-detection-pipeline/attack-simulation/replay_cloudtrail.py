"""Replay the attack CloudTrail log through the detection engine — offline.

    python 12-log-detection-pipeline/attack-simulation/replay_cloudtrail.py

The same engine the tests assert against, run over the same log, so the demo and the proof
never drift. Writes the detection board to evidence/ for a screenshot.
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT / "endon-core" / "src"), str(ROOT / "12-log-detection-pipeline" / "src")]

from endon_core.findings import Severity  # noqa: E402
from endon_siem import report  # noqa: E402
from endon_siem.engine import detect_file  # noqa: E402

FIXTURES = ROOT / "12-log-detection-pipeline" / "fixtures"
EVIDENCE = ROOT / "12-log-detection-pipeline" / "evidence"


def main() -> None:
    result = report.evaluate(detect_file(FIXTURES / "attack.json"), Severity.HIGH)
    board = report.render_console(result)
    print(board)

    EVIDENCE.mkdir(parents=True, exist_ok=True)
    (EVIDENCE / "cloudtrail-detections.txt").write_text(board + "\n", encoding="utf-8")

    clean = report.evaluate(detect_file(FIXTURES / "benign.json"), Severity.HIGH)
    print(
        f"\nBenign day: {len(clean.findings)} detection(s) — {'clean' if clean.passed else 'ALERTING'}"
    )


if __name__ == "__main__":
    main()
