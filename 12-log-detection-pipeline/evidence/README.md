# Evidence

| Evidence | Source | Status |
|---|---|---|
| [`cloudtrail-detections.txt`](cloudtrail-detections.txt) | Offline replay of the attack log — 11 detections with ATT&CK IDs; benign day is clean | Captured |
| `detections-console.png` | Terminal output of `replay_cloudtrail.py` | To capture |
| `athena-query.png` | The same detection expressed as an Athena/OpenSearch query over real CloudTrail | To capture |
| `sigma-convert.png` | `sigma convert -t splunk sigma/cloudtrail-detections.yml` producing SPL | To capture |

## Capturing live evidence

1. Run `python 12-log-detection-pipeline/attack-simulation/replay_cloudtrail.py`; screenshot it.
2. Point it at a real trail: download a CloudTrail log (or an Athena export) as JSON and run
   `endon-siem detect trail.json --alert-on HIGH`.
3. Convert the Sigma rules for your SIEM: `pip install sigma-cli && sigma convert -t splunk sigma/cloudtrail-detections.yml`; screenshot the generated query.
4. Redact account IDs and IPs before publishing.
