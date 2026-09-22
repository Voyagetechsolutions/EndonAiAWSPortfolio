"""Pod-security rules: predicates over a pod spec and its containers.

Some checks are pod-level (host namespaces, hostPath volumes, the service-account token) and
some are container-level (privileged, capabilities, resource limits, the image). Each rule
declares its scope so the scanner knows whether to evaluate it once per pod or once per
container.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from endon_k8s.manifests import PodSpec

_DANGEROUS_CAPS = {"ALL", "SYS_ADMIN", "NET_ADMIN", "NET_RAW", "SYS_PTRACE", "SYS_MODULE"}


@dataclass(frozen=True)
class PodRule:
    control_id: str
    scope: str  # "pod" or "container"
    predicate: Callable[..., bool]


def _sc(node: dict[str, Any]) -> dict[str, Any]:
    return node.get("securityContext") or {}


# ---- Container-level --------------------------------------------------------------
def _privileged(container: dict, pod: PodSpec) -> bool:
    return _sc(container).get("privileged") is True


def _allows_escalation(container: dict, pod: PodSpec) -> bool:
    return _sc(container).get("allowPrivilegeEscalation") is not False


def _runs_as_root(container: dict, pod: PodSpec) -> bool:
    for context in (_sc(container), pod.pod_security_context()):
        if context.get("runAsNonRoot") is True:
            return False
        if isinstance(context.get("runAsUser"), int) and context["runAsUser"] != 0:
            return False
    return True


def _no_limits(container: dict, pod: PodSpec) -> bool:
    limits = (container.get("resources") or {}).get("limits") or {}
    return "cpu" not in limits or "memory" not in limits


def _dangerous_caps(container: dict, pod: PodSpec) -> bool:
    added = {c.upper() for c in (_sc(container).get("capabilities") or {}).get("add") or []}
    return bool(added & _DANGEROUS_CAPS)


def _writable_root_fs(container: dict, pod: PodSpec) -> bool:
    return _sc(container).get("readOnlyRootFilesystem") is not True


def _mutable_image(container: dict, pod: PodSpec) -> bool:
    image = container.get("image", "")
    if "@sha256:" in image:
        return False
    tag = image.rsplit(":", 1)[-1] if ":" in image.rsplit("/", 1)[-1] else ""
    return tag in ("", "latest")


def _host_port(container: dict, pod: PodSpec) -> bool:
    return any(p.get("hostPort") for p in container.get("ports") or [])


# ---- Pod-level --------------------------------------------------------------------
def _host_path_volume(pod: PodSpec) -> bool:
    return any("hostPath" in v for v in pod.volumes())


def _host_namespace(pod: PodSpec) -> bool:
    return any(pod.spec.get(ns) is True for ns in ("hostNetwork", "hostPID", "hostIPC"))


def _token_automounted(pod: PodSpec) -> bool:
    return pod.spec.get("automountServiceAccountToken") is not False


RULES: tuple[PodRule, ...] = (
    PodRule("K8S-POD-001", "container", _privileged),
    PodRule("K8S-POD-002", "container", _allows_escalation),
    PodRule("K8S-POD-003", "container", _runs_as_root),
    PodRule("K8S-POD-004", "pod", _host_path_volume),
    PodRule("K8S-POD-005", "pod", _host_namespace),
    PodRule("K8S-POD-006", "container", _no_limits),
    PodRule("K8S-POD-007", "container", _dangerous_caps),
    PodRule("K8S-POD-008", "container", _writable_root_fs),
    PodRule("K8S-POD-009", "container", _mutable_image),
    PodRule("K8S-POD-010", "pod", _token_automounted),
    PodRule("K8S-POD-011", "container", _host_port),
)
