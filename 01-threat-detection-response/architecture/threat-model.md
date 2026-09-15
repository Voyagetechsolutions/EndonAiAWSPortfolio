# Threat Model: Automated Threat Detection & Response

## Scope

The response engine, its event routing, its IAM role, the incident store and the
alerting path, as deployed by `EndonPlatform` and `EndonDetectionResponse` into one
AWS account and region.

## Assets

| Asset | Why it matters |
|---|---|
| Workload resources (IAM principals, EC2, S3 data) | What the attacker is after |
| Audit logs (CloudTrail) | Needed to reconstruct any incident; the attacker's first target |
| Evidence (instance state, incident timeline, evidence bucket) | Needed for investigation, root cause and legal follow-up |
| The response engine's IAM role | Can change IAM, EC2 and S3 across the account |
| Detection routing (EventBridge rules, GuardDuty) | Disabling it silently blinds the platform |

## Attackers

| Attacker | Starting position | Goal |
|---|---|---|
| **External, stolen keys** | Valid IAM user access key | Discovery, persistence, data access, resource hijacking |
| **External, compromised workload** | Code execution on an EC2 instance (SSRF, RCE) | Steal instance-role credentials, mine, pivot |
| **Malicious or compromised insider** | Limited IAM permissions in the account | Abuse the responder: lock out colleagues, hide activity |
| **Supply chain** | Write access to the repository or pipeline | Ship modified response code with the responder's permissions |

## Attack path and coverage

| Stage | ATT&CK technique | Detected by | Response |
|---|---|---|---|
| Initial access with stolen keys | T1078.004 Valid Accounts: Cloud Accounts | GuardDuty `UnauthorizedAccess:IAMUser/*` | Deactivate keys, deny-all quarantine |
| Discovery | T1580 Cloud Infrastructure Discovery | GuardDuty `Recon:IAMUser/*`, `Discovery:*` | Alert only |
| Persistence | T1098.001 Additional Cloud Credentials | Contained indirectly: **all** keys on the user are deactivated | Extra users or roles flagged for investigation |
| Defense evasion | T1562.008 Disable or Modify Cloud Logs | GuardDuty `Stealth:IAMUser/CloudTrailLoggingDisabled` | Restart logging; contain the principal at MEDIUM+ |
| Credential access from a workload | T1552.005 Cloud Instance Metadata API | GuardDuty `InstanceCredentialExfiltration.*` | Revoke role sessions, request forensics |
| Collection | T1530 Data from Cloud Storage | GuardDuty `Policy:S3/*`, `Exfiltration:S3/*` | Re-enable Block Public Access; contain the actor |
| Impact | T1496 Resource Hijacking | GuardDuty `CryptoCurrency:EC2/*`, `Backdoor:EC2/*` | Isolate the instance, preserve evidence |

## Threats against the responder (STRIDE)

| # | Category | Threat | Mitigation | Verified by |
|---|---|---|---|---|
| S1 | Spoofing | Insider publishes a fake "compromised user" finding on the Endon bus to lock out a colleague | Rule allowlists producer sources. The normalizer overwrites the payload's `source` with the envelope's. Containment playbooks require `aws.guardduty` / `aws.securityhub`, which EventBridge refuses to accept from `PutEvents` | `test_forged_detection_on_the_endon_bus_cannot_lock_out_a_user`, `test_endon_findings_never_select_principal_or_host_containment` |
| S2 | Spoofing | Custom Security Hub finding imported with `BatchImportFindings` | Only findings from `:product/aws/` product ARNs are acted on | `test_custom_security_hub_findings_are_not_trusted` |
| T1 | Tampering | Rule added to the quarantine security group re-opens isolated instances | Group rules are revoked on every isolation | `test_tampered_quarantine_group_is_reset` |
| T2 | Tampering | Attacker stops CloudTrail to hide the containment of their access | Logging is restarted automatically; responder calls are logged once it resumes | `test_cloudtrail_logging_is_restored` |
| T3 | Tampering | Evidence altered after collection | Object Lock (governance, 90 days), versioning, KMS, access logs | `test_evidence_bucket_is_immutable_and_private` |
| R1 | Repudiation | No record of what the automation changed, or why | Every action is recorded on the incident with target, result and time; resources are tagged with the incident ID; CloudTrail records every API call | `test_compromised_user_is_contained` |
| I1 | Information disclosure | Incident data exposes sensitive details | Incidents, alerts and logs are encrypted with a customer-managed key; alerts contain identifiers, never secrets | `test_platform_data_is_encrypted_and_retained` |
| D1 | Denial of service | Responder turned against availability, e.g. isolating an instance that is merely being scanned | Targets of probes and brute force are flagged, not isolated; recon is alert-only; severity gates on containment | `test_probed_instance_is_flagged_not_isolated`, `test_brute_force_direction_decides_between_compromise_and_exposure` |
| D2 | Denial of service | Break-glass admin or a public website bucket contained during an incident | `endon:protected=true` tag honoured by guardrails | `test_protected_user_is_left_for_humans`, `test_intentionally_public_bucket_is_protected` |
| D3 | Denial of service | Responder silently failing (throttling, bugs, bad deploys) | Retries, DLQ, alarms on function errors and dead letters | `test_responder_failures_raise_alarms` |
| E1 | Elevation of privilege | Compromised responder code grants its own role more permissions | Explicit deny on modifying its own role; deployment only through the pipeline (Project 7) | `test_responder_cannot_modify_its_own_role` |
| E2 | Elevation of privilege | Crafted finding makes the responder revoke its own sessions or modify AWS service roles | Guardrails refuse the responder's role and `/aws-service-role/`, `/aws-reserved/` paths; IAM deny on those paths as defense in depth | `test_responder_never_revokes_its_own_role`, `test_service_linked_roles_are_never_modified` |

## Residual risks

| Risk | Why it remains | Planned treatment |
|---|---|---|
| Responder code compromise could misuse `iam:PutUserPolicy` on other users | IAM cannot restrict the *content* of an inline policy | Signed, reviewed deployments through GitHub OIDC (Project 7); SCP protection of the responder (Project 6) |
| An account administrator can delete the EventBridge rules or the function | Same-account administrators are trusted by IAM | SCPs deny changes to `endon-*` resources outside the pipeline role (Project 6) |
| Detection latency before containment | Determined by GuardDuty | Accepted; measured in live evidence |
| Attacker persistence other than access keys | Automatically deleting identities is unsafe | Flagged for investigation; IAM analyzer (Project 2) surfaces new principals |
