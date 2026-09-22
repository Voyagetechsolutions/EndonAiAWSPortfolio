# Evidence

| Evidence | Source | Status |
|---|---|---|
| [`scan-insecure.txt`](scan-insecure.txt) | Offline scan of the insecure plan — 15 findings, gate FAILED; hardened plan gate PASSED | Captured |
| `scan-console.png` | Terminal output of `scan_insecure_stack.py` | To capture |
| `ci-gate-fail.png` | A CI run where the scanner blocks a pull request that adds an insecure resource | To capture |
| `ci-gate-pass.png` | The same PR, fixed, passing the gate | To capture |

## Capturing live evidence

1. Run `python 09-terraform-iac-scanner/attack-simulation/scan_insecure_stack.py`; screenshot the board.
2. In a repo, add the scanner as a CI step before `terraform apply`:
   `terraform show -json plan.out > plan.json && endon-tfscan scan plan.json --fail-on HIGH`.
3. Open a PR that adds an insecure resource; screenshot the failing check.
4. Fix it; screenshot the passing check.
