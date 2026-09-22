# Evidence

| Evidence | Source | Status |
|---|---|---|
| [`azure-scan.txt`](azure-scan.txt) | Offline scan of the insecure subscription (9 findings, gate FAILED); hardened passes | Captured |
| `scan-console.png` | Terminal output of `scan_insecure_subscription.py` | To capture |
| `resource-graph.png` | The `az graph query` / portal view of the flagged resource | To capture |
| `defender-plan.png` | Microsoft Defender for Cloud plan set to Standard after remediation | To capture |

## Capturing live evidence

1. Run `python 11-azure-posture/attack-simulation/scan_insecure_subscription.py`; screenshot it.
2. In a subscription, export resources: `az graph query -q "Resources | project id,name,type,location,resourceGroup,properties" -o json > resources.json`.
3. `endon-azure scan resources.json --fail-on HIGH`; screenshot the findings.
4. Or run live: `pip install endon-azure[live] && az login && endon-azure scan --live --subscription <id>`.
5. Redact subscription IDs before publishing.
