# Security Notes: Threat Detection & Response

See the repository-wide [SECURITY.md](../SECURITY.md) for vulnerability reporting.

## Operating the response engine safely

1. **Deploy in dry-run** (the default) and review incidents from real findings in your
   environment before enabling `enforce`.
2. **Tag break-glass identities** and intentionally public buckets with `endon:protected=true`.
3. **Subscribe the alerts topic** to a monitored channel. The engine reports every
   containment, and its own failures through CloudWatch alarms.
4. **Restrict who can modify the stack.** The response role is powerful; changes should
   come only through the CI/CD pipeline.

## Reversing a containment

| Action | How to reverse |
|---|---|
| Access keys deactivated | `aws iam update-access-key --status Active` (after rotating) |
| IAM user quarantined | Delete inline policy `EndonQuarantineDenyAll` |
| Role sessions revoked | Delete inline policy `EndonRevokeOlderSessions` |
| Instance isolated | Restore the groups recorded in the incident (`originalSecurityGroups`) or the `endon:original-security-groups` tag; disable termination protection |
| S3 Block Public Access enabled | Re-evaluate first. Only disable if the bucket is meant to be public, and tag it `endon:protected=true` |

## Attack simulations

`attack-simulation/simulate_credential_compromise.py` creates a deliberately weak IAM
user. Run it only in a dedicated lab account, and always run `cleanup` afterwards.
