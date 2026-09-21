"""Red-team the CI/CD trust and the deploy role — offline, no AWS account.

Two questions:
  1. Who can assume the deploy role? (a fork, a feature branch, a PR should all fail.)
  2. If the pipeline is compromised, what can it actually do? (escalation and data
     destruction should all be denied by the identity policy and the permissions boundary.)

Both are answered by the same engines the tests assert against, so the demo and the proof
never drift.

    python 07-github-oidc-cicd/attack-simulation/compromised_pipeline.py
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [
    str(ROOT / "endon-core" / "src"),
    str(ROOT / "02-iam-security-analyzer" / "src"),
    str(ROOT / "07-github-oidc-cicd" / "src"),
]

from endon_pipeline.report import render_console  # noqa: E402


def main() -> None:
    print(render_console())


if __name__ == "__main__":
    main()
