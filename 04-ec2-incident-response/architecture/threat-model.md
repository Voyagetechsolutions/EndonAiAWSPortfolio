# Threat Model: EC2 Forensics

## Scope

The forensics engine, its collectors, its IAM role, and the evidence it writes. The engine
consumes `Endon Forensics Requested` and produces an immutable evidence package. It never
changes the instance under investigation.

## Assets

| Asset | Why it matters |
|---|---|
| Volatile + disk evidence from the instance | The record of what the attacker did; perishable |
| The chain-of-custody manifest | What makes the evidence defensible; must be trustworthy and immutable |
| The compromised instance's live state | Evidence that terminating the host would destroy |
| The forensics role | Can snapshot volumes and read across the account |

## Threats (STRIDE)

| # | Category | Threat | Mitigation | Verified by |
|---|---|---|---|---|
| T1 | Tampering | Evidence altered or deleted after collection | SHA-256 per artifact; Object Lock (WORM) + versioning + KMS; role denied `s3:DeleteObject` and `s3:BypassGovernanceRetention` | `test_manifest_is_written_to_object_lock_bucket`, `test_destructive_actions_are_explicitly_denied` |
| T2 | Tampering | The manifest is forged or altered | Manifest hashed and stored under Object Lock; collector identity recorded | manifest hash in the completion event |
| D1 | Denial (of evidence) | The host is terminated/stopped, destroying volatile state | The engine never stops/terminates; explicit IAM deny on Terminate/Stop | `test_instance_is_never_terminated`, `test_forensics_role_has_no_destructive_ec2_permissions` |
| D2 | Denial (of evidence) | One failing collector aborts the whole case | Each collector is isolated; failures are recorded, the rest run | `test_one_failing_collector_does_not_lose_the_case` |
| E1 | Elevation | The forensics role is compromised and abused destructively | Read + snapshot + evidence-write only; explicit deny on every destructive EC2/S3 action | `test_forensics_role_has_no_destructive_ec2_permissions` |
| S1 | Spoofing | A forged forensics request causes needless snapshots | Consumes only `Endon Forensics Requested` from `endon.detection`; snapshotting is non-destructive and idempotent | `test_deployed_pattern_matches_project1_forensics_event`, `test_redelivery_does_not_recollect` |
| I1 | Information disclosure | Evidence (which may contain sensitive data) leaks | Stored only in the KMS-encrypted, Block-Public-Access, Object Lock bucket | platform stack (`test_evidence_bucket_is_immutable_and_private`) |
| R1 | Repudiation | No defensible record of collection | Chain-of-custody manifest: ordered, timestamped, hashed, attributed to the collector role | `test_manifest_is_written_to_object_lock_bucket` |

## The isolation / live-response trade-off

Isolating an instance to a no-traffic security group (Project 1's containment) is the right
default, but it makes SSM-based volatile collection impossible. This is an accepted,
documented residual gap rather than a bug:

| Option | Evidence | Risk |
|---|---|---|
| Full isolation (default) | No volatile memory; disk + metadata + console preserved | Safest; a documented `SKIPPED` gap |
| Quarantine SG allows SSM VPC-endpoint egress only | Volatile memory collectable | The host retains a narrow, controlled network path |

## Residual risks

| Risk | Why it remains | Treatment |
|---|---|---|
| Volatile memory not collected on a fully isolated host | Isolation removes network reachability | Documented `SKIPPED`; opt-in SSM-endpoint egress for live response |
| Snapshots, not bit-for-bit disk images | AWS-native, non-disruptive collection | Sufficient for most cloud IR; imaging is a possible extension |
| An account admin could delete evidence with governance bypass | Object Lock GOVERNANCE can be bypassed with a specific permission | The forensics role is denied it; restrict `s3:BypassGovernanceRetention` org-wide via SCP (Project 6), or use COMPLIANCE mode for legal holds |
