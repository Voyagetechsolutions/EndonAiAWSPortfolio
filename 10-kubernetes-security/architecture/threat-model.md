# Threat Model: Kubernetes Security

## Scope

Static analysis of Kubernetes manifests (pod security + RBAC) and an admission-control decision
over pods. The goal is to stop a container from becoming root on the node, and a ServiceAccount
from becoming cluster-admin — by catching the configuration in CI and refusing the pod at
admission.

## Assets

| Asset | Why it matters |
|---|---|
| The node / host | A privileged or host-mounting pod is a breakout to the node |
| Cluster Secrets | Cluster-wide Secret read exposes every credential |
| RBAC itself | `bind`/`escalate` and cluster-admin bindings let a subject grant itself anything |
| The API server | Pod creation and `pods/exec` are paths to running arbitrary privileged workloads |

## Attackers / failure sources

| Source | Position | Concern |
|---|---|---|
| Compromised container | Runs in a pod | Break out to the node if the pod is privileged/host-mounted |
| Over-broad ServiceAccount | A token in a pod | Read all Secrets, create privileged pods, escalate RBAC |
| Careless author | Opens a PR with a manifest | The common case — a debug pod left privileged, a wildcard role |
| Insider | Can write RBAC | A quiet `cluster-admin` binding or an `escalate` grant |

## Threats and controls

| # | Threat | Control | Proven by |
|---|---|---|---|
| 1 | Privileged container → node compromise | K8S-POD-001 (+ admission deny) | benchmark, `test_admission_denies...` |
| 2 | Break out via host namespace / hostPath / hostPort | K8S-POD-004 / 005 / 011 | benchmark |
| 3 | Container runs as root / escalates privilege | K8S-POD-002 / 003 | benchmark |
| 4 | Dangerous Linux capabilities (SYS_ADMIN, NET_ADMIN) | K8S-POD-007 | benchmark |
| 5 | Unbounded / unpinned / over-mounted container | K8S-POD-006 / 008 / 009 / 010 | benchmark |
| 6 | Wildcard role (verbs `*` on resources `*`) | K8S-RBAC-001 | `test_rbac_wildcard...` |
| 7 | Cluster-wide Secret read | K8S-RBAC-002 | benchmark |
| 8 | Pod creation → run a privileged pod anyway | K8S-RBAC-003 | benchmark |
| 9 | RBAC self-escalation (`bind`/`escalate`) | K8S-RBAC-004 | `test_rbac_escalation...` |
| 10 | A binding straight to cluster-admin | K8S-RBAC-005 | `test_rbac_escalation_and_binding` |
| 11 | Shell into running pods (`pods/exec`) | K8S-RBAC-006 | benchmark |
| 12 | The scanner passes an insecure manifest (false negative) | benchmark asserts all 17 controls fire | `test_every_*_control_fires...` |
| 13 | It blocks a safe manifest (false positive) | secure fixtures must produce nothing | `test_*_produces_no_findings` |

## Enforcement and its bypasses

| Bypass | Mitigation |
|---|---|
| Skip the CI scan | Enforce with an in-cluster Kyverno webhook, not only CI |
| Apply drift directly to the API (`kubectl edit`) | Kyverno `background: true` re-checks; runtime scanning is the next layer |
| Deploy a policy that doesn't do what you think | `endon-k8s admit` unit-tests the decision before `kubectl apply` |
| Loosen the block threshold | A visible, reviewable change; keep HIGH+ enforced |

## Residual risks

| Risk | Why it remains | Treatment |
|---|---|---|
| Static manifests miss live drift | It reads YAML, not cluster state | In-cluster Kyverno + a runtime scan |
| RBAC reachability is per-object | No full subject→permission graph yet | Roadmap: a P2-style RBAC escalation graph |
| The simulator is a subset of Kyverno/Rego | It models the blocking pod-security rules | The real Kyverno policies enforce in-cluster |
