# Evidence

| Evidence | Source | Status |
|---|---|---|
| [`offline-replay.txt`](offline-replay.txt) | Offline attack replay on emulated AWS | Captured |
| `detection.png` | GuardDuty console: findings from the live lab attack | To capture |
| `eventbridge-invocations.png` | CloudWatch metrics: rule matches and Lambda invocations | To capture |
| `incident-dynamodb.png` | Incident item with timeline and action records | To capture |
| `cloudtrail-response.png` | CloudTrail: `UpdateAccessKey`, `PutUserPolicy`, `ModifyNetworkInterfaceAttribute` made by the responder role | To capture |
| `alert-email.png` | SNS alert showing status and actions | To capture |
| `isolated-instance.png` | EC2 console: instance in `endon-quarantine`, termination protection on, incident tags | To capture |
| `dry-run-sample.png` | Incident from a GuardDuty sample finding showing `DRY_RUN` records | To capture |

## Capturing live evidence

1. `cdk deploy --all` (dry-run), then run `generate_sample_findings.py`. Capture `dry-run-sample.png`.
2. Redeploy with `-c endon:responseMode=enforce`.
3. Run `simulate_credential_compromise.py setup` and `attack` in the lab account.
4. Capture each screenshot above; record GuardDuty's `eventFirstSeen` and the incident's
   `contained_at` for the live results table in [CASE_STUDY.md](../CASE_STUDY.md).
5. Run `simulate_credential_compromise.py cleanup`.

Redact account IDs and IP addresses before publishing screenshots.
