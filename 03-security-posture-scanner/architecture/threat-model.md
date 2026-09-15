# Threat Model: Posture Scanner

## Scope

The scanner's collection (read-only APIs across eight services), its control evaluation,
and the report and findings it produces. Like the IAM analyzer, it detects risk and does
not change resources; the one remediation in the flow is performed by Project 1, not here.

## Assets

| Asset | Why it matters |
|---|---|
| The account's resource configuration | The thing being assessed; also reveals weaknesses |
| The posture report | A map of exactly what is exposed and how — sensitive if it leaks |
| The scanner's execution role | Account-wide read across many services |

## What the scanner defends against (in the target account)

| Misconfiguration class | Controls |
|---|---|
| Public data exposure | S3-001, S3-002, RDS-001, KMS-002 |
| Missing encryption at rest / in transit | S3-003, S3-004, EC2-005, EC2-006, RDS-002, CT-003 |
| Network exposure | EC2-001, EC2-002, EC2-003, EC2-004 |
| Credential-theft enablers | EC2-007 (IMDSv1), IAM-001/002/003 |
| Blind spots in logging / detection | CT-001, CT-002, CT-004, DET-001, DET-002 |
| Recovery gaps | S3-005, RDS-003, KMS-001 |

## Threats against the scanner (STRIDE)

| # | Category | Threat | Mitigation | Verified by |
|---|---|---|---|---|
| E1 | Elevation of privilege | The scanner is compromised and used to change the resources it audits | Read-only role; no mutating action on any audited service, enforced by the build | `test_scanner_only_has_read_only_service_permissions` |
| T1 | Tampering | A posture finding is turned into an unsafe automatic change (encrypting/closing something in production) | Only `Posture:S3/BucketPubliclyAccessible` is auto-remediated, and only by Project 1's guardrailed engine; all else is triage | `test_non_public_posture_findings_route_to_review`, Project 1 playbook rules |
| I1 | Information disclosure | The report (a map of exposures) leaks | Reports written only to the KMS-encrypted, Object-Lock evidence bucket with Block Public Access | Platform stack (`test_evidence_bucket_is_immutable_and_private`) |
| S1 | Spoofing | A forged posture finding on the bus triggers containment elsewhere | The response engine never contains on an Endon-sourced finding; posture findings reach only remediation/triage playbooks | Project 1 trust-boundary tests |
| D1 | Denial of service | One failing/denied service aborts the whole scan, hiding everything else | Per-check exceptions are caught and recorded in `errors`; the scan continues | `test_scan_runs_cleanly_across_services` (and the catch in `scanner.py`) |
| D2 | Denial of service | The scanner silently stops running, so drift accumulates unseen | CloudWatch alarm on function errors to the alerts topic | `test_scanner_reports_failures` |

## False positives and false negatives

Coverage is only meaningful next to a measured false-positive rate. The benchmark asserts
both directions:

| Decision | Direction | Rationale |
|---|---|---|
| BPA fully enabled suppresses S3-001 | avoid false positive | A public ACL that BPA neutralizes is not an active exposure |
| Conditioned wildcard S3 policy is not "public" | avoid false positive | `aws:SourceVpce`-gated access is not public |
| All-protocols open suppresses the SSH/RDP controls | reduce noise | One "all ports open" is clearer than three overlapping findings |
| Per-check failures recorded, scan continues | avoid false negative of the *whole* scan | Partial coverage beats none |
| Only 26 curated controls | accepted false negatives | Portfolio scope; breadth over exhaustiveness |

The benchmark's clean resources (hardened bucket, scoped SG, encrypted volume,
private+encrypted DB, ExternalId-gated role) are asserted to produce **zero** findings.

## Residual risks

| Risk | Why it remains | Treatment |
|---|---|---|
| Controls outside the curated 26 | Portfolio scope | Extend the catalog; the add-a-control path is one function + one control entry |
| Drift between daily scans | Point-in-time snapshots | GuardDuty (Project 1) for in-the-moment attacker changes |
| Cross-account posture | Single-account scanner | Organization-wide aggregation with the landing zone (Project 6) |
| Resource-policy / boundary nuances | Simplified evaluation in a few checks | Deeper identity analysis is Project 2; data-specific analysis is Project 5 |
