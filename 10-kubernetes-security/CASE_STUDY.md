# Case Study: Rejecting the Privileged Pod at the Door

## Context

A team runs its services on Kubernetes. To debug a networking issue, someone adds a pod that
runs `privileged: true`, mounts the host root filesystem, and shares the host network. It works,
the issue is fixed, and the pod stays — because the manifest was merged and nobody removed it.
That pod is now a permanent path from a container compromise to root on the node. Separately, a
ServiceAccount was granted `get, list secrets` cluster-wide "to make a controller work." Between
the two, a single compromised container can read every secret in the cluster and break out to
the host.

Neither needed an exploit. Both were YAML, both were reviewed, both were approved.

## Two problems, two tools

**Workloads.** Pod specs carry a dozen security-relevant switches — `privileged`, `runAsNonRoot`,
`hostPath`, `hostNetwork`, resource limits, capabilities, the image tag. The scanner reads the
manifest, extracts the pod spec out of whatever workload wrapped it (Deployment, StatefulSet,
CronJob…), and flags each insecure switch with a severity and a fix.

**RBAC.** RBAC is Kubernetes' IAM, and it fails the same way AWS IAM does — by accreting
permissions nobody revisits. So it gets the same treatment as **Project 2**: the analyzer flags
the grants that turn a modest ServiceAccount into cluster takeover — wildcard rules, cluster-wide
Secret reads, Pod creation, `bind`/`escalate` on RBAC, `pods/exec`, and any binding to
`cluster-admin`.

## The flagship: enforce it at admission, prove it offline

Finding the privileged pod in CI is good. Refusing to let it be created is better. In a real
cluster that job belongs to a validating admission webhook — Kyverno or OPA Gatekeeper — which
sees every pod before it exists and can reject it. The project ships the real Kyverno policies
*and* a Python simulation of the decision that shares the scanner's rules:

```text
denied  Deployment/default/legacy-api: privileged; host namespace; hostPath; runs as root; ...
admitted Deployment/default/hardened-api
```

That matters because it makes admission control a **unit test**. Instead of applying a policy to
a cluster and hoping, you assert offline that this policy denies this pod and admits that one —
then deploy the Kyverno version knowing it does exactly what the test says.

## Proving coverage

A deliberately insecure workload trips all 11 pod controls; insecure RBAC trips all 6; the
hardened counterparts trip none. A test asserts it:

```text
19 findings on the insecure fixtures   (CRITICAL 4  HIGH 11  MEDIUM 4)
 0 findings on the hardened fixtures
Bad pod: DENIED (7 reasons)   Hardened pod: ADMITTED
```

## One platform, cloud and cluster

Because a Kubernetes finding is the same `endon_core.Finding` as an AWS one, it lands in the same
SOC (Project 8), converts to the same ASFF, and the scanner drops into the same pipeline
(Project 7) as the AWS scanners. "How exposed are we right now?" now spans the cluster and the
cloud in one view — which is exactly how an attacker sees a modern estate.

## Takeaways

- The dangerous Kubernetes misconfigurations are configuration, not exploits — so the fix is to
  check the configuration and refuse the bad ones at admission.
- RBAC deserves the same first-class analysis as cloud IAM; it's where clusters actually get
  taken over.
- Simulating the admission decision turned "deploy the policy and see" into a test you run
  before the cluster ever sees the pod.
