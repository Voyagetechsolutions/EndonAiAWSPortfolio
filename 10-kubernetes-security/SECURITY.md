# Security Notes: Kubernetes Security

See the repository-wide [SECURITY.md](../SECURITY.md) for vulnerability reporting.

## Operating notes

- **The scanner only reads.** It parses YAML manifests and emits findings; it never talks to a
  cluster and needs no kubeconfig. Run it in CI on the manifests in the repo.
- **Enforce in the cluster, don't just scan in CI.** CI can be skipped; an admission webhook
  cannot. Deploy the Kyverno policies in [`policies/`](policies/kyverno-pod-baseline.yaml) in
  `Enforce` mode so the API server itself rejects a non-compliant pod, and use `endon-k8s admit`
  to test the policy's intent before you apply it.
- **HIGH+ is the enforcement line.** The gate and the admission simulator block on HIGH and
  CRITICAL; MEDIUM findings (writable root fs, mutable tag, auto-mounted token) are reported.
  Moving a control across that line is a deliberate risk decision.
- **RBAC is the crown jewels.** Treat the RBAC findings — cluster-admin bindings, wildcard
  roles, cluster-wide Secret access — with the same seriousness as an admin-equivalent AWS
  policy. They are the fastest path to cluster takeover.

## Scope and blind spots

- **Static manifests, not live state.** Drift applied directly to the API server (`kubectl edit`),
  Helm-templated values resolved at deploy time, and admission mutations aren't visible to a
  manifest scan. Enforce with in-cluster policy; consider a runtime/cluster-state scan too.
- **Per-object RBAC.** The analyzer flags dangerous grants on each Role/ClusterRole/binding; it
  does not yet compute the full subject→role→permission reachability graph (the P2-style next
  step).
- **The simulator models the blocking pod-security subset,** not the full Kyverno/Rego language.

## Deploying the Kyverno policies

```bash
kubectl apply -f policies/kyverno-pod-baseline.yaml   # Enforce mode
kubectl apply -f manifests/insecure.yaml              # rejected by the webhook
kubectl apply -f manifests/secure.yaml                # admitted
```

Roll new policies out in `Audit` mode first (they report without blocking), confirm nothing
legitimate is caught, then switch to `Enforce`.
