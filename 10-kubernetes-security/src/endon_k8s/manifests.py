"""Load Kubernetes manifests and pull the pod spec out of any workload kind.

A manifest file is a multi-document YAML stream. Every workload — a Deployment, StatefulSet,
DaemonSet, Job, CronJob or a bare Pod — ends up running a *pod spec*, just nested at a
different depth. This module normalizes all of them to a single ``PodSpec`` so the pod-security
rules never have to care which workload wrapped the pod.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

# Where the pod template lives inside each workload kind.
_POD_PATHS: dict[str, tuple[str, ...]] = {
    "Pod": ("spec",),
    "Deployment": ("spec", "template", "spec"),
    "ReplicaSet": ("spec", "template", "spec"),
    "StatefulSet": ("spec", "template", "spec"),
    "DaemonSet": ("spec", "template", "spec"),
    "Job": ("spec", "template", "spec"),
    "CronJob": ("spec", "jobTemplate", "spec", "template", "spec"),
}


@dataclass(frozen=True)
class K8sObject:
    kind: str
    name: str
    namespace: str
    raw: dict[str, Any]

    @property
    def ref(self) -> str:
        return f"{self.kind}/{self.namespace}/{self.name}"


@dataclass(frozen=True)
class PodSpec:
    """A workload's pod spec, with its containers already flattened."""

    owner: K8sObject
    spec: dict[str, Any]
    containers: list[dict[str, Any]] = field(default_factory=list)

    def pod_security_context(self) -> dict[str, Any]:
        return self.spec.get("securityContext") or {}

    def volumes(self) -> list[dict[str, Any]]:
        return self.spec.get("volumes") or []


def load(text: str) -> list[K8sObject]:
    """Parse a multi-document YAML string into Kubernetes objects."""
    objects: list[K8sObject] = []
    for doc in yaml.safe_load_all(text):
        if not isinstance(doc, dict) or "kind" not in doc:
            continue
        meta = doc.get("metadata") or {}
        objects.append(
            K8sObject(
                kind=doc["kind"],
                name=meta.get("name", "<unnamed>"),
                namespace=meta.get("namespace", "default"),
                raw=doc,
            )
        )
    return objects


def load_file(path: str | Path) -> list[K8sObject]:
    return load(Path(path).read_text(encoding="utf-8"))


def pod_specs(objects: list[K8sObject]) -> list[PodSpec]:
    """Extract a PodSpec from every workload object; skip anything without one."""
    specs: list[PodSpec] = []
    for obj in objects:
        path = _POD_PATHS.get(obj.kind)
        if not path:
            continue
        spec = _dig(obj.raw, path)
        if not isinstance(spec, dict):
            continue
        containers = list(spec.get("initContainers") or []) + list(spec.get("containers") or [])
        specs.append(PodSpec(owner=obj, spec=spec, containers=containers))
    return specs


def _dig(node: Any, path: tuple[str, ...]) -> Any:
    for key in path:
        if not isinstance(node, dict):
            return None
        node = node.get(key)
    return node
