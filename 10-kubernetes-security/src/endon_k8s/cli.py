"""Command line for the Kubernetes scanner and admission simulator.

endon-k8s scan manifests/            # scan a file or directory of manifests
endon-k8s scan app.yaml --fail-on HIGH
endon-k8s admit pod.yaml             # simulate the admission webhook (exit 1 if denied)
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from endon_core.findings import Severity
from endon_k8s import report
from endon_k8s.admission import review
from endon_k8s.manifests import load_file, pod_specs
from endon_k8s.scanner import scan


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="endon-k8s", description="Endon AI Kubernetes security.")
    sub = parser.add_subparsers(dest="command", required=True)

    scan_cmd = sub.add_parser("scan", help="scan manifests for pod-security and RBAC issues")
    scan_cmd.add_argument("path", help="a manifest file or a directory of *.yaml")
    scan_cmd.add_argument(
        "--fail-on", choices=[s.value for s in Severity], default=Severity.HIGH.value
    )
    scan_cmd.add_argument("--json", action="store_true")

    admit_cmd = sub.add_parser("admit", help="simulate admission control on the pods in a manifest")
    admit_cmd.add_argument("path", help="a manifest file")
    return parser


def _manifest_paths(path: str) -> list[Path]:
    p = Path(path)
    if p.is_dir():
        return sorted(list(p.glob("*.yaml")) + list(p.glob("*.yml")))
    return [p]


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "scan":
        return _scan(args)
    if args.command == "admit":
        return _admit(args)
    return 1


def _scan(args: argparse.Namespace) -> int:
    objects = [o for path in _manifest_paths(args.path) for o in load_file(path)]
    result = report.evaluate_gate(scan(objects), Severity(args.fail_on))
    print(report.render_json(result) if args.json else report.render_console(result))
    if not result.passed:
        print(
            f"GATE FAILED: {result.blocking} finding(s) at or above {args.fail_on}.",
            file=sys.stderr,
        )
        return 1
    return 0


def _admit(args: argparse.Namespace) -> int:
    denied = False
    # Admission control is about pods, so only review objects that carry a pod spec.
    for spec in pod_specs(load_file(args.path)):
        response = review(spec.owner)
        stream = sys.stdout if response.allowed else sys.stderr
        print(("ADMIT  " if response.allowed else "DENY   ") + response.message(), file=stream)
        denied = denied or not response.allowed
    return 1 if denied else 0


if __name__ == "__main__":
    raise SystemExit(main())
