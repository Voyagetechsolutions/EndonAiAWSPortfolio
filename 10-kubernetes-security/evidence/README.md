# Evidence

| Evidence | Source | Status |
|---|---|---|
| [`k8s-scan.txt`](k8s-scan.txt) | Offline scan (19 findings) + admission control denying the bad pod, admitting the hardened one | Captured |
| `scan-console.png` | Terminal output of `deploy_bad_pod.py` | To capture |
| `kyverno-block.png` | `kubectl apply` of the insecure pod rejected by Kyverno on a `kind` cluster | To capture |
| `kyverno-admit.png` | The hardened pod admitted by the same policies | To capture |

## Capturing live evidence (with a local cluster)

1. Run `python 10-kubernetes-security/attack-simulation/deploy_bad_pod.py`; screenshot the board.
2. `kind create cluster` and install Kyverno.
3. `kubectl apply -f policies/kyverno-pod-baseline.yaml`.
4. `kubectl apply -f manifests/insecure.yaml` — screenshot the admission-webhook rejection.
5. `kubectl apply -f manifests/secure.yaml` — screenshot it being admitted.
6. Confirm the offline `endon-k8s admit` decision matches Kyverno's.
