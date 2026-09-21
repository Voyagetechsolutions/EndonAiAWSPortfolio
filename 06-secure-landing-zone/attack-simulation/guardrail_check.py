"""Red-team the landing zone: a full workload-account admin tries the dangerous moves.

No AWS account is used. The SCP simulator evaluates each attempt against the guardrails
that apply to the Production account, and prints which are blocked. This is the governance
equivalent of the other projects' attack simulations: it proves the controls hold, offline.

    python 06-secure-landing-zone/attack-simulation/guardrail_check.py
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT / "endon-core" / "src"), str(ROOT / "06-secure-landing-zone" / "src")]

from endon_landingzone.report import render_console  # noqa: E402


def main() -> None:
    print(render_console())


if __name__ == "__main__":
    main()
