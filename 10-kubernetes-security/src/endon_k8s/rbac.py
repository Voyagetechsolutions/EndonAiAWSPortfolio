"""RBAC analysis: over-permissioned Roles/ClusterRoles and dangerous bindings.

RBAC is Kubernetes' IAM, and it drifts toward over-permission the same way AWS IAM does. These
checks flag the grants that turn a modest ServiceAccount into cluster takeover: wildcard rules,
cluster-wide Secret reads, pod creation (a path to running privileged pods), RBAC escalation
verbs, exec-into-pods, and any binding straight to cluster-admin.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable
from dataclasses import dataclass

from endon_k8s.manifests import K8sObject

_ROLE_KINDS = {"Role", "ClusterRole"}
_BINDING_KINDS = {"RoleBinding", "ClusterRoleBinding"}
_RBAC_RESOURCES = {"roles", "clusterroles", "rolebindings", "clusterrolebindings"}


@dataclass(frozen=True)
class RbacRule:
    control_id: str
    predicate: Callable[[K8sObject], bool]


def _rules(role: K8sObject) -> list[dict]:
    return role.raw.get("rules") or []


def _matches(rule: dict, key: str, wanted: Iterable[str]) -> bool:
    values = {str(v).lower() for v in (rule.get(key) or [])}
    return bool(values & {w.lower() for w in wanted})


def _has_verb_on(role: K8sObject, verbs: Iterable[str], resources: Iterable[str]) -> bool:
    for rule in _rules(role):
        rverbs = {str(v).lower() for v in (rule.get("verbs") or [])}
        wants_verb = "*" in rverbs or bool(rverbs & {v.lower() for v in verbs})
        if wants_verb and _matches(rule, "resources", list(resources) + ["*"]):
            return True
    return False


def _wildcard(role: K8sObject) -> bool:
    return any(
        "*" in (rule.get("verbs") or []) and "*" in (rule.get("resources") or [])
        for rule in _rules(role)
    )


def _reads_secrets(role: K8sObject) -> bool:
    return _has_verb_on(role, ("get", "list", "watch"), ("secrets",))


def _creates_pods(role: K8sObject) -> bool:
    return _has_verb_on(role, ("create",), ("pods",))


def _rbac_escalation(role: K8sObject) -> bool:
    return any(
        _matches(rule, "verbs", ("bind", "escalate"))
        and _matches(rule, "resources", _RBAC_RESOURCES)
        for rule in _rules(role)
    )


def _pod_exec(role: K8sObject) -> bool:
    return any(_matches(rule, "resources", ("pods/exec", "pods/attach")) for rule in _rules(role))


def _binds_cluster_admin(binding: K8sObject) -> bool:
    return (binding.raw.get("roleRef") or {}).get("name") == "cluster-admin"


ROLE_RULES: tuple[RbacRule, ...] = (
    RbacRule("K8S-RBAC-001", _wildcard),
    RbacRule("K8S-RBAC-002", _reads_secrets),
    RbacRule("K8S-RBAC-003", _creates_pods),
    RbacRule("K8S-RBAC-004", _rbac_escalation),
    RbacRule("K8S-RBAC-006", _pod_exec),
)
BINDING_RULES: tuple[RbacRule, ...] = (RbacRule("K8S-RBAC-005", _binds_cluster_admin),)


def evaluate(obj: K8sObject) -> list[str]:
    """Return the RBAC control IDs this object violates."""
    if obj.kind in _ROLE_KINDS:
        return [r.control_id for r in ROLE_RULES if r.predicate(obj)]
    if obj.kind in _BINDING_KINDS:
        return [r.control_id for r in BINDING_RULES if r.predicate(obj)]
    return []
