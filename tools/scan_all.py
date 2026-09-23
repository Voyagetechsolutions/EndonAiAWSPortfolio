"""Run every offline Endon scanner and write one SARIF file each — the whole platform in one pass.

    python tools/scan_all.py                 # scan the example fixtures, write evidence/sarif/*.sarif
    python tools/scan_all.py --out out/       # choose the output directory

Each scanner already emits SARIF from its own CLI (``--sarif``). This driver runs all five over
their committed example fixtures in a single process so CI (see .github/workflows/security-scan.yml)
can upload the results to GitHub code scanning, and so the platform can be demonstrated locally with
one command. It always exits 0 — it is a reporting pass, not a gate; the per-scanner CLIs are the
gates. Findings for every scanner are proven by the tests; this simply serializes them to SARIF.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

# The scanners live in per-project src trees that are not installed; put them on the path
# the same way the tests (pyproject pythonpath) and the attack-simulation scripts do.
_SRC = [
    ROOT / "endon-core" / "src",
    ROOT / "02-iam-security-analyzer" / "src",  # tfscan reuses the IAM policy engine
    ROOT / "09-terraform-iac-scanner" / "src",
    ROOT / "10-kubernetes-security" / "src",
    ROOT / "11-azure-posture" / "src",
    ROOT / "12-log-detection-pipeline" / "src",
    ROOT / "13-finops-cost-guardrails" / "src",
]
sys.path[:0] = [str(p) for p in _SRC]

from endon_core.findings import Finding  # noqa: E402
from endon_core.sarif import render_sarif  # noqa: E402


def _tfscan() -> list[Finding]:
    from endon_tfscan.plan import Plan
    from endon_tfscan.scanner import scan

    return scan(Plan.from_file(ROOT / "09-terraform-iac-scanner/terraform/plans/insecure.plan.json"))


def _k8s() -> list[Finding]:
    from endon_k8s.manifests import load_file
    from endon_k8s.scanner import scan

    manifests = ROOT / "10-kubernetes-security/manifests"
    objects = [o for name in ("insecure.yaml", "rbac-insecure.yaml") for o in load_file(manifests / name)]
    return scan(objects)


def _azure() -> list[Finding]:
    from endon_azure.resources import load_file
    from endon_azure.scanner import scan

    return scan(load_file(ROOT / "11-azure-posture/fixtures/insecure.json"))


def _siem() -> list[Finding]:
    from endon_siem.engine import detect_file

    return detect_file(ROOT / "12-log-detection-pipeline/fixtures/attack.json")


def _finops() -> list[Finding]:
    from endon_finops.engine import analyze_file

    return analyze_file(ROOT / "13-finops-cost-guardrails/fixtures/anomalous.json")


# (output filename, SARIF tool name, callable). One entry per shipped scanner.
SCANNERS = [
    ("terraform", "endon-tfscan", _tfscan),
    ("kubernetes", "endon-k8s", _k8s),
    ("azure", "endon-azure", _azure),
    ("cloudtrail", "endon-siem", _siem),
    ("finops", "endon-finops", _finops),
]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run every Endon scanner and write SARIF.")
    parser.add_argument("--out", default="evidence/sarif", help="output directory for *.sarif")
    args = parser.parse_args(argv)

    out_dir = (ROOT / args.out).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    print("ENDON AI — full-platform scan")
    print("=" * 30)
    total = 0
    for name, tool_name, run in SCANNERS:
        findings = run()
        total += len(findings)
        (out_dir / f"{name}.sarif").write_text(
            render_sarif(findings, tool_name=tool_name), encoding="utf-8"
        )
        print(f"  {tool_name:<14} {len(findings):>3} finding(s) -> {name}.sarif")
    print("-" * 30)
    print(f"  {total} finding(s) across {len(SCANNERS)} scanners; SARIF in {out_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
