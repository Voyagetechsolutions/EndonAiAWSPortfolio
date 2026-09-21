"""Show the whole platform through the SOC - offline, no AWS account.

Seeds the incident and finding stores with the output every other project produces (a
GuardDuty containment, an IAM escalation path, a public bucket auto-closed by Project 1, an
exposed secret), then prints the SOC board and writes a static HTML render of the dashboard so
the console can be screenshotted without deploying anything.

    python 08-security-operations-center/attack-simulation/soc_walkthrough.py
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [
    str(ROOT / "endon-core" / "src"),
    str(ROOT / "08-security-operations-center" / "src"),
]

from endon_soc import report  # noqa: E402
from endon_soc.demo import seed_stores  # noqa: E402
from endon_soc.health import HealthStatus, ServiceHealth  # noqa: E402
from endon_soc.render import render  # noqa: E402
from endon_soc.service import SocService  # noqa: E402

# A realistic health mix: detection on, but Security Hub not yet enabled (a blind spot).
DEMO_HEALTH = [
    ServiceHealth("GuardDuty", HealthStatus.ACTIVE, "1 detector"),
    ServiceHealth("Security Hub", HealthStatus.INACTIVE, "Hub not enabled"),
    ServiceHealth("CloudTrail", HealthStatus.ACTIVE, "org-trail logging"),
    ServiceHealth("AWS Config", HealthStatus.ACTIVE, "recorder on"),
]

EVIDENCE = ROOT / "08-security-operations-center" / "evidence"


def main() -> None:
    incidents, findings = seed_stores()
    service = SocService(incidents, findings, health=DEMO_HEALTH)

    board = report.render_console(service)
    print(board)

    EVIDENCE.mkdir(parents=True, exist_ok=True)
    (EVIDENCE / "soc-board.txt").write_text(board + "\n", encoding="utf-8")

    summary = service.summary()
    html = render(
        "dashboard.html",
        summary=summary,
        incidents=service.incidents(limit=25),
        account_id="123456789012",
        region="us-east-1",
        generated_at=summary.generated_at,
    )
    (EVIDENCE / "dashboard.html").write_text(html, encoding="utf-8")
    print(f"\nWrote {EVIDENCE / 'soc-board.txt'} and {EVIDENCE / 'dashboard.html'}")


if __name__ == "__main__":
    main()
