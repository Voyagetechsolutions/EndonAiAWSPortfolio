"""The Kubernetes control catalog: pod-security and RBAC misconfigurations.

Finding types follow ``K8s:<Area>/<Name>`` so a Kubernetes finding rides the same bus, stores
and reports as everything else. Pod-security controls map to Infrastructure Security; RBAC
controls map to Identity & Access Management — the same split the SCS-C03 exam uses.
"""

from __future__ import annotations

from dataclasses import dataclass

from endon_core.findings import Domain, Severity


@dataclass(frozen=True)
class Control:
    id: str
    area: str
    title: str
    severity: Severity
    finding_type: str
    domain: Domain
    remediation: str


def _c(cid, area, name, title, severity, domain, remediation) -> Control:
    return Control(cid, area, title, severity, f"K8s:{area}/{name}", domain, remediation)


_POD = Domain.INFRASTRUCTURE
_RBAC = Domain.IAM

_ALL = [
    # --- Pod security ---------------------------------------------------------------
    _c(
        "K8S-POD-001",
        "Pod",
        "PrivilegedContainer",
        "Container runs privileged",
        Severity.CRITICAL,
        _POD,
        "Remove securityContext.privileged; grant only the capabilities needed.",
    ),
    _c(
        "K8S-POD-002",
        "Pod",
        "AllowsPrivilegeEscalation",
        "Container allows privilege escalation",
        Severity.HIGH,
        _POD,
        "Set securityContext.allowPrivilegeEscalation = false.",
    ),
    _c(
        "K8S-POD-003",
        "Pod",
        "RunsAsRoot",
        "Container may run as root",
        Severity.HIGH,
        _POD,
        "Set runAsNonRoot = true (and a non-zero runAsUser).",
    ),
    _c(
        "K8S-POD-004",
        "Pod",
        "HostPathVolume",
        "Pod mounts a hostPath volume",
        Severity.HIGH,
        _POD,
        "Remove hostPath mounts; use a proper volume type.",
    ),
    _c(
        "K8S-POD-005",
        "Pod",
        "HostNamespace",
        "Pod shares a host namespace",
        Severity.HIGH,
        _POD,
        "Set hostNetwork/hostPID/hostIPC to false.",
    ),
    _c(
        "K8S-POD-006",
        "Pod",
        "NoResourceLimits",
        "Container has no CPU/memory limits",
        Severity.MEDIUM,
        _POD,
        "Set resources.limits for cpu and memory to bound a compromised container.",
    ),
    _c(
        "K8S-POD-007",
        "Pod",
        "DangerousCapabilities",
        "Container adds dangerous Linux capabilities",
        Severity.HIGH,
        _POD,
        "Drop ALL capabilities and add back only what is required.",
    ),
    _c(
        "K8S-POD-008",
        "Pod",
        "WritableRootFilesystem",
        "Container root filesystem is writable",
        Severity.MEDIUM,
        _POD,
        "Set readOnlyRootFilesystem = true.",
    ),
    _c(
        "K8S-POD-009",
        "Pod",
        "MutableImageTag",
        "Container image is not pinned",
        Severity.MEDIUM,
        _POD,
        "Pin the image by digest (@sha256:...) instead of :latest or a floating tag.",
    ),
    _c(
        "K8S-POD-010",
        "Pod",
        "ServiceAccountTokenMounted",
        "Service-account token is auto-mounted",
        Severity.MEDIUM,
        _POD,
        "Set automountServiceAccountToken = false unless the pod calls the API.",
    ),
    _c(
        "K8S-POD-011",
        "Pod",
        "HostPortExposed",
        "Container binds a host port",
        Severity.HIGH,
        _POD,
        "Remove hostPort; expose the pod through a Service instead.",
    ),
    # --- RBAC -----------------------------------------------------------------------
    _c(
        "K8S-RBAC-001",
        "RBAC",
        "WildcardPermission",
        "Role grants wildcard verbs on wildcard resources",
        Severity.CRITICAL,
        _RBAC,
        "Replace '*' with the specific verbs and resources the workload needs.",
    ),
    _c(
        "K8S-RBAC-002",
        "RBAC",
        "ClusterSecretsAccess",
        "Role can read Secrets",
        Severity.HIGH,
        _RBAC,
        "Scope secret access to a namespace and specific secret names.",
    ),
    _c(
        "K8S-RBAC-003",
        "RBAC",
        "PodCreate",
        "Role can create Pods",
        Severity.HIGH,
        _RBAC,
        "Pod creation allows running privileged/host-mounting pods; grant only where needed.",
    ),
    _c(
        "K8S-RBAC-004",
        "RBAC",
        "RbacEscalation",
        "Role can bind or escalate RBAC",
        Severity.CRITICAL,
        _RBAC,
        "Remove bind/escalate on roles/clusterroles; it lets a subject grant itself more.",
    ),
    _c(
        "K8S-RBAC-005",
        "RBAC",
        "ClusterAdminBinding",
        "Binding grants cluster-admin",
        Severity.CRITICAL,
        _RBAC,
        "Bind a least-privilege role instead of cluster-admin.",
    ),
    _c(
        "K8S-RBAC-006",
        "RBAC",
        "PodExec",
        "Role can exec into Pods",
        Severity.HIGH,
        _RBAC,
        "pods/exec and pods/attach give shell access to running containers; restrict it.",
    ),
]

BY_ID: dict[str, Control] = {c.id: c for c in _ALL}


def all_controls() -> list[Control]:
    return list(_ALL)


def get(control_id: str) -> Control:
    return BY_ID[control_id]
