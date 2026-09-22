"""Manifest parsing across workload kinds, and the CLI gate."""

import json
from pathlib import Path

from endon_k8s import cli
from endon_k8s.manifests import load, pod_specs

MANIFESTS = Path(__file__).resolve().parents[1] / "manifests"


def test_pod_spec_extraction_from_workload_kinds():
    manifest = load(
        """
apiVersion: batch/v1
kind: CronJob
metadata: {name: job}
spec:
  jobTemplate:
    spec:
      template:
        spec:
          containers:
            - {name: c, image: busybox:latest}
---
apiVersion: apps/v1
kind: StatefulSet
metadata: {name: db}
spec:
  template:
    spec:
      initContainers:
        - {name: init, image: init:latest}
      containers:
        - {name: db, image: db:latest}
"""
    )
    specs = pod_specs(manifest)
    assert len(specs) == 2
    # The StatefulSet's initContainer and container are both flattened for scanning.
    assert len(specs[1].containers) == 2


def test_non_workload_docs_are_skipped():
    manifest = load("apiVersion: v1\nkind: Service\nmetadata: {name: s}\nspec: {}\n")
    assert pod_specs(manifest) == []


def test_cli_scan_fails_on_insecure(capsys):
    code = cli.main(["scan", str(MANIFESTS / "insecure.yaml"), "--fail-on", "HIGH"])
    assert code == 1
    captured = capsys.readouterr()
    assert "GATE FAILED" in captured.err
    assert "KUBERNETES SECURITY SCAN" in captured.out


def test_cli_scan_passes_on_secure(capsys):
    assert cli.main(["scan", str(MANIFESTS / "secure.yaml"), "--fail-on", "HIGH"]) == 0
    assert "PASSED" in capsys.readouterr().out


def test_cli_scan_directory_and_json(capsys):
    code = cli.main(["scan", str(MANIFESTS), "--fail-on", "CRITICAL", "--json"])
    assert code == 1
    data = json.loads(capsys.readouterr().out)
    assert data["scanner"] == "endon-k8s"
    assert data["by_severity"]["CRITICAL"] >= 1


def test_cli_admit_denies_insecure_pod(capsys):
    code = cli.main(["admit", str(MANIFESTS / "insecure.yaml")])
    assert code == 1
    assert "DENY" in capsys.readouterr().err


def test_cli_admit_admits_secure_pod(capsys):
    code = cli.main(["admit", str(MANIFESTS / "secure.yaml")])
    assert code == 0
    assert "ADMIT" in capsys.readouterr().out
