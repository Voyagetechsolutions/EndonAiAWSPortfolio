# Threat Model: IAM Analyzer

## Scope

The analyzer's collection (read-only IAM APIs), its evaluation engine, and the assessment
it produces. The analyzer detects risks; it does not change IAM. Its own privilege is
therefore part of the model.

## Assets

| Asset | Why it matters |
|---|---|
| The account's IAM configuration | The thing being assessed; also sensitive (reveals structure and weaknesses) |
| The assessment report | Names exploitable escalation paths — a roadmap if it leaks |
| The analyzer's execution role | Runs in the security account with account-wide IAM read |

## What the analyzer defends the account against

| Risk in the target account | Detection |
|---|---|
| Over-privileged identities (admin, wildcards) | admin + wildcard checks |
| Privilege escalation to administrator | escalation engine + assume-role graph |
| Confused-deputy trust (external account, no ExternalId) | trust check |
| Publicly assumable roles (`Principal:"*"`) | trust check |
| Long-lived / unused / unrotated credentials, no MFA, root keys | credential + root checks |

## Threats against the analyzer (STRIDE)

| # | Category | Threat | Mitigation | Verified by |
|---|---|---|---|---|
| E1 | Elevation of privilege | The analyzer is compromised and used to modify IAM | The role has **no** IAM write permission — only Get/List/Generate/Simulate | `test_analyzer_never_has_iam_write_permissions` |
| T1 | Tampering | Findings are turned into automatic IAM changes that cause an outage or are abused | IAM findings route to `iam-risk-review` (alert only); the response engine never contains on an Endon-sourced finding | `test_response_engine_routes_iam_findings_to_review_not_containment` (Project 2), Project 1 playbook rules |
| I1 | Information disclosure | The report (an escalation roadmap) leaks | Reports are written only to the KMS-encrypted, Object-Lock evidence bucket with Block Public Access; alerts carry identifiers, not policy contents | Platform stack (`test_evidence_bucket_is_immutable_and_private`) |
| S1 | Spoofing | A forged IAM finding on the bus triggers real containment elsewhere | The response engine restricts containment to AWS-native detectors; Endon findings can only reach review playbooks | Project 1 `test_endon_findings_never_select_principal_or_host_containment` |
| D1 | Denial of service | The analyzer silently stops running, so drift goes unseen | CloudWatch alarm on function errors to the alerts topic | `test_analyzer_reports_failures` |
| R1 | Repudiation | No record of what a given assessment found | Every run stores a timestamped HTML + JSON report in the immutable evidence bucket | handler stores report |

## False positives and false negatives

The analyzer is explicit about where it sits on this trade-off:

| Decision | Direction | Rationale |
|---|---|---|
| Conditional grants reported, down-weighted | toward false positives | A gated grant can still be exploitable; a human should see it |
| Scoped escalation grants reported as `conditional-or-scoped` | toward false positives | Scoping reduces but rarely eliminates the risk |
| Assume-role edge needs both assume permission and admitting trust | toward false negatives | Inventing paths that cannot actually be taken would destroy trust in the tool |
| External trust with `sts:ExternalId` produces no finding | toward false negatives | This is the documented correct configuration |
| Resource policies and boundaries not evaluated as limiters | toward false positives | Identity policy is assessed; a boundary that would block a path is noted as remediation, not used to suppress |

## Residual risks

| Risk | Why it remains | Treatment |
|---|---|---|
| A permissions boundary or SCP would actually block a reported path | Boundaries are not yet evaluated as limiters | Reported as "add/verify a boundary"; boundary-aware evaluation is future work |
| Resource-policy-based access (cross-account S3/KMS) | Out of scope for an identity analyzer | Covered in part by the posture scanner (Project 3) and data protection monitor (Project 5) |
| Cross-account escalation chains | Single-account graph today | Extended with the multi-account landing zone (Project 6) |
| Drift between daily scans | Point-in-time snapshots | GuardDuty (Project 1) and the posture scanner catch in-the-moment changes |
