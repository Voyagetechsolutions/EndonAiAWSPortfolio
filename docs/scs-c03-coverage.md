# SCS-C03 Domain Coverage

The AWS Certified Security – Specialty (SCS-C03) exam guide organizes cloud security
into six domains. Endon AI uses those domains as its specification: every domain is
backed by working code, not just by a description.

Status key: **Built** = implemented and tested · *Planned* = designed, not yet built.

## 1. Detection

| Capability | Component | Status |
|------------|-----------|--------|
| Route GuardDuty and Security Hub findings through EventBridge | Project 1 | **Built** |
| Normalize findings from multiple detectors into one model (ASFF-compatible) | endon-core, Project 1 | **Built** |
| Distinguish attacker (ACTOR) from victim (TARGET) resources | Project 1 | **Built** |
| Alert on failures of the detection pipeline itself (errors, DLQ) | Project 1 | **Built** |
| Detect misconfigurations across S3, EC2, RDS, CloudTrail, KMS, IAM (26 controls) | Project 3 | **Built** |
| Detection-rate benchmark against a known-vulnerable environment | Project 3 | **Built** |
| Detect disabled detective controls (GuardDuty, Config) | Project 3 | **Built** |
| Central SOC view of findings and incidents (one read-only console) | Project 8 | **Built** |
| Explainable security score from open findings + detective-control health | Project 8 | **Built** |
| Live detective-control health panel, fail-safe (unconfirmed = blind spot) | Project 8 | **Built** |

## 2. Incident Response

| Capability | Component | Status |
|------------|-----------|--------|
| Automated containment of compromised IAM users (deactivate keys, deny-all quarantine) | Project 1 | **Built** |
| Revoke stolen temporary credentials (`aws:TokenIssueTime` deny) | Project 1 | **Built** |
| Isolate EC2 instances, including cutting existing tracked connections | Project 1 | **Built** |
| Preserve evidence: termination protection, ASG detachment, no deletion | Project 1 | **Built** |
| Restore CloudTrail logging after tampering | Project 1 | **Built** |
| Incident timeline and time-to-contain measurement | endon-core, Project 1 | **Built** |
| Automated forensic collection in order of volatility | Project 4 | **Built** |
| EBS snapshots, metadata and console capture with SHA-256 integrity | Project 4 | **Built** |
| Immutable chain-of-custody manifest (S3 Object Lock WORM) | Project 4 | **Built** |
| Preserve-only forensics role (no terminate/delete), enforced by tests | Project 4 | **Built** |
| Incident timeline surfaced detection-to-containment in one console (Cognito-gated, read-only) | Project 8 | **Built** |

## 3. Infrastructure Security

| Capability | Component | Status |
|------------|-----------|--------|
| Quarantine security group enforcement (re-verified on every use) | Project 1 | **Built** |
| Network exposure checks (0.0.0.0/0 on admin ports, default SGs) | Project 3 | **Built** |
| Encryption-at-rest checks (EBS, RDS, S3, KMS rotation) | Project 3 | **Built** |
| IMDSv2 enforcement check | Project 3 | **Built** |
| Region and service restrictions through SCPs | Project 6 | **Built** |

## 4. Identity and Access Management

| Capability | Component | Status |
|------------|-----------|--------|
| Least-privilege response role, verified by synthesized-template tests | Project 1 | **Built** |
| Explicit deny to stop the responder from modifying itself | Project 1 | **Built** |
| Effective-permission evaluation engine (deny-wins, wildcard, NotAction) | Project 2 | **Built** |
| Administrator-equivalent detection from policy documents | Project 2 | **Built** |
| Privilege-escalation path detection (e.g. `iam:PassRole` + `lambda:CreateFunction`) | Project 2 | **Built** |
| Transitive escalation through the assume-role graph | Project 2 | **Built** |
| Dangerous role trust policies (external account, `Principal:"*"`) | Project 2 | **Built** |
| Credential hygiene: root keys, no-MFA console users, stale/unused keys | Project 2 | **Built** |
| Least-privilege policy generation from Access Advisor | Project 2 | **Built** |
| Keyless CI/CD with GitHub OIDC federation (no long-lived AWS keys) | Project 7 | **Built** |
| Deploy-role trust pinned to one repo + branch (`sub`/`aud` conditions), proven by a simulator | Project 7 | **Built** |
| Permissions boundary caps a compromised pipeline (deny-wins escalation containment) | Project 7 | **Built** |
| Pipeline security gates: IAM analysis (Project 2) + posture scan (Project 3) block insecure deploys | Project 7 | **Built** |

## 5. Data Protection

| Capability | Component | Status |
|------------|-----------|--------|
| Automated S3 Block Public Access remediation | Project 1 | **Built** |
| Customer-managed KMS encryption for all platform data, key rotation | endon-core | **Built** |
| Immutable evidence storage with S3 Object Lock | endon-core | **Built** |
| Secret-detection engine (signatures + entropy) with irreversible redaction | Project 5 | **Built** |
| Secrets in Lambda env vars, EC2 user data; Secrets Manager rotation | Project 5 | **Built** |
| Macie sensitive-data findings; public sensitive data auto-remediated via Project 1 | Project 5 | **Built** |
| AWS Health exposed-credential events normalized to findings | Project 5 | **Built** |
| Monitor never reads or emits a secret's plaintext (enforced by tests) | Project 5 | **Built** |

## 6. Security Foundations and Governance

| Capability | Component | Status |
|------------|-----------|--------|
| Infrastructure as code for every resource (AWS CDK, Python) | All | **Built** |
| Protected-resource tagging convention honoured by automation | Project 1 | **Built** |
| Multi-account structure: Security, Log Archive, workload OUs | Project 6 | **Built** |
| Organization-wide CloudTrail (org trail to Object Lock Log Archive) | Project 6 | **Built** |
| SCPs: protect logging/detection, deny unapproved regions, prevent public S3, deny root | Project 6 | **Built** |
| SCP simulator proving guardrails hold against a workload admin | Project 6 | **Built** |
| SCP protecting the Endon platform from account admins (closes Project 1 residual risk) | Project 6 | **Built** |
| Org security-services baseline with delegated admin (Config, GuardDuty, Security Hub, Macie) | Project 6 | **Built** |
