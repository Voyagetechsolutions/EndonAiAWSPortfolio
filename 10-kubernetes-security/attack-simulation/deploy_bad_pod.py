"""Scan the insecure manifests and show admission control rejecting the bad pod — offline.

    python 10-kubernetes-security/attack-simulation/deploy_bad_pod.py

The same rules the tests assert against, run over the same fixtures, so the demo and the proof
never drift. Writes the board to evidence/ for a screenshot.
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [
    str(ROOT / "endon-core" / "src"),
    str(ROOT / "10-kubernetes-security" / "src"),
]

from endon_core.findings import Severity  # noqa: E402
from endon_k8s import report  # noqa: E402
from endon_k8s.admission import review  # noqa: E402
from endon_k8s.manifests import load_file  # noqa: E402
from endon_k8s.scanner import scan  # noqa: E402

MANIFESTS = ROOT / "10-kubernetes-security" / "manifests"
EVIDENCE = ROOT / "10-kubernetes-security" / "evidence"


def main() -> None:
    objects = load_file(MANIFESTS / "insecure.yaml") + load_file(MANIFESTS / "rbac-insecure.yaml")
    result = report.evaluate_gate(scan(objects), fail_on=Severity.HIGH)
    board = report.render_console(result)

    lines = [board, "", "ADMISSION CONTROL (what a validating webhook would do)", "-" * 52]
    for obj in load_file(MANIFESTS / "insecure.yaml"):
        lines.append("  " + review(obj).message())
    for obj in load_file(MANIFESTS / "secure.yaml"):
        lines.append("  " + review(obj).message())
    output = "\n".join(lines)
    print(output)

    EVIDENCE.mkdir(parents=True, exist_ok=True)
    (EVIDENCE / "k8s-scan.txt").write_text(output + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
