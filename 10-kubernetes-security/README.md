# Project 10 · Kubernetes Security

> Part of the [Endon AI](../README.md) platform · **Status: built and tested** · Python + Kyverno

Three things every Kubernetes security review needs, built to plug into the same platform:
a **workload scanner** (privileged containers, host namespaces, missing limits, mutable
images), an **RBAC analyzer** (the cluster's IAM — wildcards, cluster-wide Secret reads, RBAC
escalation, cluster-admin bindings), and an **admission-control simulator** that decides — the
way a validating webhook does — whether a pod may be created at all.

---

## The Security Problem

A container that runs `privileged` with the host root filesystem mounted is, effectively, root
on the node. A ServiceAccount with `get secrets` cluster-wide can read every credential in the
cluster. A RoleBinding to `cluster-admin` is game over. None of these need an exploit — they're
just *configuration*, shipped in a YAML file, approved in a pull request. The place to catch
them is the manifest, and the place to *stop* them is admission: before the pod exists.

**Goal:** find these misconfigurations in manifests with the same severity model and finding
format as the rest of the platform, analyze RBAC the way Project 2 analyzes IAM, and prove the
admission policy that will guard the cluster actually rejects the dangerous pod.

## What it checks

[`controls.py`](src/endon_k8s/controls.py) is the catalog: **11 pod-security** controls
(Infrastructure Security) and **6 RBAC** controls (Identity & Access Management).

**Pod security** ([`podsec.py`](src/endon_k8s/podsec.py)) — privileged container, allows
privilege escalation, runs as root, hostPath volume, host namespace (`hostNetwork/PID/IPC`),
no resource limits, dangerous Linux capabilities, writable root filesystem, mutable image tag
(`:latest`), auto-mounted service-account token, host port.

**RBAC** ([`rbac.py`](src/endon_k8s/rbac.py)) — RBAC is the cluster's IAM, and it drifts toward
over-permission the same way: wildcard verbs on wildcard resources, cluster-wide Secret reads,
Pod creation (a path to running a privileged pod), `bind`/`escalate` on RBAC objects, `pods/exec`,
and any binding straight to `cluster-admin`.

## The admission simulator (the flagship)

A validating admission webhook (Kyverno, OPA Gatekeeper) is what actually *enforces* pod
security — it sees every pod before creation and can reject it. [`admission.py`](src/endon_k8s/admission.py)
is that decision, in Python: run the blocking (HIGH+) pod rules over a workload and deny it if
any fire. It shares the scanner's rules, so the gate and the audit never disagree, and — the
real point — it lets the policy be **unit-tested offline**: deny the dangerous pod, admit the
hardened one, before anything touches a cluster.

```bash
python 10-kubernetes-security/attack-simulation/deploy_bad_pod.py
```

```text
  19 finding(s)   CRITICAL 4  HIGH 11  MEDIUM 4
  Gate (fail-on HIGH): FAILED — 15 blocking

ADMISSION CONTROL (what a validating webhook would do)
  denied  Deployment/default/legacy-api: K8S-POD-001 privileged; K8S-POD-005 host namespace;
          K8S-POD-004 hostPath; K8S-POD-003 runs as root; ... 7 reasons
  admitted Deployment/default/hardened-api
```

The [`policies/`](policies/kyverno-pod-baseline.yaml) directory holds the **real Kyverno
ClusterPolicies** — the deployable, in-cluster version of the same intent. The simulator is how
you prove they'll do what you think before `kubectl apply`.

## Proving coverage, not claiming it

Like the posture (Project 3) and Terraform (Project 9) benchmarks, coverage is measured. A
deliberately insecure workload trips **all 11** pod controls and insecure RBAC trips **all 6**;
their hardened counterparts trip none. The [benchmark test](tests/test_benchmark.py) asserts
exactly that.

## How it connects to the platform

| Direction | Contract |
|---|---|
| Emits | `endon_core.Finding` (`K8s:Pod/*`, `K8s:RBAC/*`), so results reach the bus, stores, SOC and ASFF like any producer |
| Mirrors | Project 2 for IAM → this does for **RBAC** what P2 does for AWS IAM |
| Gates | `endon-k8s scan --fail-on HIGH` slots into the Project 7 pipeline next to the other scanners |
| Enforces | The admission simulator (and the Kyverno policies) stop a bad pod at creation |

## Security Decisions

1. **Scan the manifest, enforce at admission.** Detection in CI is good; a webhook that refuses
   the pod is better. The same rules drive both, so they can't drift apart.
2. **Treat RBAC like IAM.** Over-permission is the cluster's biggest risk; it gets the same
   first-class analysis as AWS IAM.
3. **Prove the policy offline.** `endon-k8s admit` lets the exact enforcement decision be
   unit-tested before it reaches a cluster.
4. **Block on HIGH+, report the rest.** The gate and the webhook reject on HIGH and CRITICAL;
   MEDIUM findings are reported, not enforced.

## Limitations

- **Static manifests, not live cluster state.** It reads YAML, so drift applied straight to the
  API server (`kubectl edit`) or admission mutations aren't seen — that's what the in-cluster
  Kyverno policies and a runtime scanner cover.
- **RBAC reachability is per-object.** It flags dangerous grants; it does not yet compute the
  full subject→role→permission graph across every binding (the natural next step, mirroring
  Project 2's escalation graph).
- **The simulator models the pod-security subset** a webhook would block; it is not a full
  Kyverno/Rego engine.

## Lessons Learned

- **RBAC is where clusters get owned.** A privileged container is loud; a quiet `get secrets`
  cluster-wide is how an attacker actually pivots. Analyzing RBAC mattered as much as pod specs.
- **The webhook decision belongs in a test.** Being able to assert "this policy denies this pod"
  offline turned admission control from a cluster experiment into a unit test.
- **One finding format pays off again.** A Kubernetes finding lands in the same SOC as an AWS
  one, so "how exposed are we?" spans the cluster and the cloud.

## Run It

```bash
python 10-kubernetes-security/attack-simulation/deploy_bad_pod.py   # scan + admission proof
pytest 10-kubernetes-security/tests                                 # tests (17)
endon-k8s scan 10-kubernetes-security/manifests --fail-on HIGH
endon-k8s admit 10-kubernetes-security/manifests/insecure.yaml      # simulate the webhook
```

## Project Layout

```text
10-kubernetes-security/
├── README.md · CASE_STUDY.md · SECURITY.md
├── architecture/{architecture.md, threat-model.md}
├── src/endon_k8s/
│   ├── manifests.py   load YAML, pull the pod spec out of any workload kind
│   ├── controls.py    the control catalog (11 pod + 6 RBAC)
│   ├── podsec.py      pod-security predicates (pod- and container-scope)
│   ├── rbac.py        RBAC over-permission analysis
│   ├── scanner.py     rules -> endon_core Findings
│   ├── admission.py   validating-webhook simulator (the flagship)
│   └── report.py / cli.py
├── policies/          real Kyverno ClusterPolicies (deployable)
├── manifests/         insecure/secure workload + RBAC fixtures
├── attack-simulation/deploy_bad_pod.py
├── evidence/
└── tests/
```
