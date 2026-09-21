# Evidence

| Evidence | Source | Status |
|---|---|---|
| [`guardrail-check.txt`](guardrail-check.txt) | Offline guardrail proof (10/10 blocked) + OU tree + baseline | Captured |
| `guardrail-console.png` | Terminal output of `guardrail_check.py` | To capture |
| `scp-console.png` | The SCPs attached in the AWS Organizations console | To capture |
| `ou-tree.png` | The OU structure in the console | To capture |
| `denied-in-console.png` | A real AccessDenied when a workload admin tries a blocked action | To capture |
| `org-trail.png` | The organization CloudTrail delivering to the Log Archive Object Lock bucket | To capture |

## Capturing live evidence

1. Run `guardrail_check.py`; screenshot the guardrail proof.
2. In a test organization, deploy the stack (`cdk deploy -c endon:orgRootId=... -c
   endon:organizationId=...`). Screenshot the OUs and attached SCPs in the console.
3. From a role in the Production account, attempt a blocked action (e.g.
   `aws cloudtrail stop-logging`) and capture the `AccessDenied` (with an SCP explanation).
4. Show the org trail and its Object Lock retention on the Log Archive bucket.
5. Redact account IDs and the organization id before publishing.
