# Evidence

| Evidence | Source | Status |
|---|---|---|
| [`cost-guardrails.txt`](cost-guardrails.txt) | Offline analysis of the anomalous bill — 6 findings incl. cryptomining + egress spikes; clean bill passes | Captured |
| `analysis-console.png` | Terminal output of `analyze_cryptomining_spike.py` | To capture |
| `cost-explorer-spike.png` | The compute/egress spike in AWS Cost Explorer | To capture |
| `guardduty-correlation.png` | The GuardDuty cryptomining finding for the same day/instance | To capture |

## Capturing live evidence

1. Run `python 13-finops-cost-guardrails/attack-simulation/analyze_cryptomining_spike.py`; screenshot it.
2. Export real cost data:
   `aws ce get-cost-and-usage --time-period Start=<d1>,End=<d2> --granularity DAILY --metrics UnblendedCost --group-by Type=DIMENSION,Key=SERVICE Type=DIMENSION,Key=REGION` and flatten to the `rows` shape.
3. `endon-finops analyze costs.json --fail-on HIGH`; screenshot the findings.
4. Correlate a compute spike with the GuardDuty cryptomining finding for the same window.
