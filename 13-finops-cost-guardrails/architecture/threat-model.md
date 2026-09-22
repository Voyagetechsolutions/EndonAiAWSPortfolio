# Threat Model: FinOps + Security-Cost Guardrails

## Scope

Analysis of AWS cost data for waste and for security-relevant cost anomalies. The goal is to use
the bill — a signal finance already collects — as an early, corroborating detector for the classes
of compromise that cost money, and to cut waste in the same pass.

## Assets

| Asset | Why it matters |
|---|---|
| The AWS bill | Attacker compute/egress is spend the company pays for |
| Account data (S3) | Egress cost is the invoice-side shadow of exfiltration |
| Compute capacity | A cryptominer's whole purpose is to consume it |
| Cost accountability | Untagged spend has no owner and hides anomalies |

## Attackers / failure sources

| Source | Position | Cost shape |
|---|---|---|
| Cryptomining attacker | Compromised credentials | Compute spike, often in an unused region |
| Exfiltration attacker | Read access to data | Data-transfer-out spike |
| Careless team | Deploys resources | Idle Elastic IPs, untagged spend, a budget-busting day |

## Threats and controls

| # | Threat | Control | Proven by |
|---|---|---|---|
| 1 | Cryptomining (resource hijacking) | FIN-101 compute spike | benchmark, `test_spike_primitive` |
| 2 | Data exfiltration | FIN-102 egress spike | benchmark |
| 3 | Evasion via an unused region | FIN-103 new-region spend | `test_new_region...` |
| 4 | Runaway cost / budget breach | FIN-003 daily anomaly | benchmark |
| 5 | Unaccountable spend | FIN-001 untagged spend | benchmark |
| 6 | Waste (idle resources) | FIN-002 idle Elastic IPs | benchmark |
| 7 | Analyzer misses the attack (false negative) | benchmark asserts all 6 fire | `test_every_control_fires...` |
| 8 | Analyzer fires on a steady bill (false positive) | clean fixture must be empty | `test_the_clean_export...` |

## Ways it can mislead (and the answer)

| Concern | Mitigation |
|---|---|
| A legitimate load test spikes compute | Findings say "possible" and name day/region/multiple; a human confirms before acting |
| Cheap variance triggers alerts | Dollar floors: nothing fires below a threshold |
| Cost data lags reality | It's a corroborating signal; pair with GuardDuty (Project 1) and CloudTrail detections (Project 12) |
| A miner stays under the spike factor | This is defence in depth, not the only detector; the log and native detectors still fire |

## Residual risks

| Risk | Why it remains | Treatment |
|---|---|---|
| Simple median-and-multiple statistics | Chosen for explainability and testability | Seasonal/holiday-aware baselining is future work |
| Coarse, delayed cost data | Cost Explorer/CUR granularity | Run daily; treat as early corroboration, not real-time |
| A spike is a lead, not proof | By design | Correlate across signals in the SOC before remediation |
