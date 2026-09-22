"""The admission-control simulator and the RBAC analyzer in detail."""

from endon_k8s import rbac
from endon_k8s.admission import review
from endon_k8s.manifests import K8sObject, load


def test_admission_denies_the_insecure_pod(insecure_pods):
    response = review(insecure_pods[0])
    assert not response.allowed
    # It explains why, naming the controls a real webhook would reject on.
    joined = " ".join(response.reasons)
    assert "K8S-POD-001" in joined  # privileged
    assert "DENY" not in response.message() or "denied" in response.message()


def test_admission_admits_the_hardened_pod(secure_pods):
    response = review(secure_pods[0])
    assert response.allowed
    assert response.reasons == []


def test_admission_blocks_only_on_high_and_above():
    # A pod whose only issue is MEDIUM (writable root fs) is admitted — the gate blocks HIGH+.
    only_medium = load(
        """
apiVersion: v1
kind: Pod
metadata: {name: mild, namespace: default}
spec:
  automountServiceAccountToken: false
  securityContext: {runAsNonRoot: true, runAsUser: 1000}
  containers:
    - name: c
      image: app@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
      resources: {limits: {cpu: "100m", memory: "64Mi"}}
      securityContext:
        allowPrivilegeEscalation: false
        readOnlyRootFilesystem: false
        capabilities: {drop: ["ALL"]}
"""
    )[0]
    assert review(only_medium).allowed


def _role(kind: str, name: str, rules: list[dict]) -> K8sObject:
    return K8sObject(kind, name, "default", {"kind": kind, "rules": rules})


def test_rbac_wildcard_and_secrets():
    wildcard = _role("ClusterRole", "god", [{"verbs": ["*"], "resources": ["*"]}])
    secrets = _role("ClusterRole", "sec", [{"verbs": ["get"], "resources": ["secrets"]}])
    scoped = _role("Role", "cfg", [{"verbs": ["get"], "resources": ["configmaps"]}])
    assert "K8S-RBAC-001" in rbac.evaluate(wildcard)
    assert "K8S-RBAC-002" in rbac.evaluate(secrets)
    assert rbac.evaluate(scoped) == []


def test_rbac_escalation_and_binding():
    escalate = _role(
        "ClusterRole",
        "esc",
        [
            {
                "apiGroups": ["rbac.authorization.k8s.io"],
                "verbs": ["escalate"],
                "resources": ["clusterroles"],
            }
        ],
    )
    binding = K8sObject(
        "ClusterRoleBinding",
        "b",
        "default",
        {"kind": "ClusterRoleBinding", "roleRef": {"name": "cluster-admin"}},
    )
    safe_binding = K8sObject(
        "ClusterRoleBinding",
        "s",
        "default",
        {"kind": "ClusterRoleBinding", "roleRef": {"name": "config-reader"}},
    )
    assert "K8S-RBAC-004" in rbac.evaluate(escalate)
    assert "K8S-RBAC-005" in rbac.evaluate(binding)
    assert rbac.evaluate(safe_binding) == []
