# Security Notes: FinOps + Security-Cost Guardrails

See the repository-wide [SECURITY.md](../SECURITY.md) for vulnerability reporting.

## Operating notes

- **Read-only over a cost export.** The analyzer consumes Cost Explorer / CUR JSON and emits
  findings; it never calls AWS and needs no credentials. Least privilege for pulling the data live
  is `ce:GetCostAndUsage` (or read access to the CUR S3 bucket) — nothing more.
- **The spike findings mean "investigate," not "block."** FIN-101/102 are HIGH because a compute or
  egress surge is often the earliest sign of compromise — but a load test or batch job spikes too.
  Treat them as leads that name the day, region and multiple, and correlate with GuardDuty and the
  CloudTrail detections (Project 12) before acting.
- **Tune the floors and factors per account.** A tiny account and a large one have different
  baselines; the dollar floors and spike multiples are the knobs. Keep them in code review.
- **Cost data lags.** Cost Explorer/CUR update on a delay, so this is a corroborating signal, not a
  real-time detector. Run it daily.

## Trust and scope

- **A cost spike is a signal, not proof.** Every security-cost finding is phrased as "possible" and
  carries the arithmetic, so a human confirms before an instance is terminated or a bill is
  disputed.
- **Simple statistics by design.** Median-and-multiple is explainable and testable; it is not a
  seasonal/holiday-aware model. That refinement is future work, not a hidden black box.
- **No resource actions.** The analyzer never stops instances or releases IPs — it reports. Any
  remediation (killing a miner, releasing an idle EIP) is a separate, authorized action.

## Using it

```bash
# From a Cost Explorer export flattened to daily line items:
aws ce get-cost-and-usage --time-period Start=<d1>,End=<d2> --granularity DAILY \
  --metrics UnblendedCost --group-by Type=DIMENSION,Key=SERVICE Type=DIMENSION,Key=REGION
# -> flatten to {"rows": [{date, service, usage_type, region, amount, tags}, ...]}
endon-finops analyze costs.json --fail-on HIGH
```
