"""Scan Kubernetes objects into Endon findings.

Pod-security rules run over each workload's pod spec (pod-scope once, container-scope per
container); RBAC rules run over Roles, ClusterRoles and their bindings. Everything comes out as
``endon_core.Finding`` objects — the same type the AWS scanners produce — so a Kubernetes
finding reaches the platform's bus, stores, SOC and ASFF with no special-casing.
"""

from __future__ import annotations

from endon_core.findings import Finding, Resource
from endon_k8s import podsec, rbac
from endon_k8s.controls import Control, get
from endon_k8s.manifests import K8sObject, PodSpec, load, load_file, pod_specs

SOURCE = "endon.k8s"


def scan(objects: list[K8sObject]) -> list[Finding]:
    findings: list[Finding] = []
    findings.extend(_scan_pods(pod_specs(objects)))
    findings.extend(_scan_rbac(objects))
    findings.sort(
        key=lambda f: (-f.severity.rank, f.type, f.resources[0].id if f.resources else "")
    )
    return findings


def scan_text(text: str) -> list[Finding]:
    return scan(load(text))


def scan_file(path) -> list[Finding]:
    return scan(load_file(path))


def _scan_pods(specs: list[PodSpec]) -> list[Finding]:
    findings: list[Finding] = []
    for spec in specs:
        for rule in podsec.RULES:
            fired = (
                rule.predicate(spec)
                if rule.scope == "pod"
                else any(rule.predicate(c, spec) for c in spec.containers)
            )
            if fired:
                findings.append(_finding(get(rule.control_id), spec.owner.ref))
    return findings


def _scan_rbac(objects: list[K8sObject]) -> list[Finding]:
    findings: list[Finding] = []
    for obj in objects:
        for control_id in rbac.evaluate(obj):
            findings.append(_finding(get(control_id), obj.ref))
    return findings


def _finding(control: Control, ref: str) -> Finding:
    return Finding(
        source=SOURCE,
        type=control.finding_type,
        title=control.title,
        severity=control.severity,
        account_id="kubernetes",
        region="cluster",
        domain=control.domain,
        resources=[Resource(type="KubernetesObject", id=ref, region="cluster")],
        description=f"{control.title} ({ref}).",
        remediation=control.remediation,
        control_id=control.id,
        tags={"platform": "kubernetes"},
    )
