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
| Detect misconfigurations across S3, EC2, IAM, CloudTrail, KMS, RDS | Project 3 | *Planned* |
| Central SOC view of findings and incidents | Project 8 | *Planned* |

## 2. Incident Response

| Capability | Component | Status |
|------------|-----------|--------|
| Automated containment of compromised IAM users (deactivate keys, deny-all quarantine) | Project 1 | **Built** |
| Revoke stolen temporary credentials (`aws:TokenIssueTime` deny) | Project 1 | **Built** |
| Isolate EC2 instances, including cutting existing tracked connections | Project 1 | **Built** |
| Preserve evidence: termination protection, ASG detachment, no deletion | Project 1 | **Built** |
| Restore CloudTrail logging after tampering | Project 1 | **Built** |
| Incident timeline and time-to-contain measurement | endon-core, Project 1 | **Built** |
| EBS snapshots, metadata capture, evidence chain of custody | Project 4 | *Planned* |

## 3. Infrastructure Security

| Capability | Component | Status |
|------------|-----------|--------|
| Quarantine security group enforcement (re-verified on every use) | Project 1 | **Built** |
| Network exposure checks (0.0.0.0/0 on admin ports, default SGs) | Project 3 | *Planned* |
| Region and service restrictions through SCPs | Project 6 | *Planned* |

## 4. Identity and Access Management

| Capability | Component | Status |
|------------|-----------|--------|
| Least-privilege response role, verified by synthesized-template tests | Project 1 | **Built** |
| Explicit deny to stop the responder from modifying itself | Project 1 | **Built** |
| Wildcard permissions, stale credentials and unused permissions | Project 2 | *Planned* |
| Privilege-escalation path detection (e.g. `iam:PassRole` + `lambda:CreateFunction`) | Project 2 | *Planned* |
| Keyless CI/CD with GitHub OIDC and scoped deployment roles | Project 7 | *Planned* |

## 5. Data Protection

| Capability | Component | Status |
|------------|-----------|--------|
| Automated S3 Block Public Access remediation | Project 1 | **Built** |
| Customer-managed KMS encryption for all platform data, key rotation | endon-core | **Built** |
| Immutable evidence storage with S3 Object Lock | endon-core | **Built** |
| Macie sensitive-data findings with automated bucket restriction | Project 5 | *Planned* |
| Secrets in Lambda environment variables, overly broad KMS key policies | Project 5 | *Planned* |

## 6. Security Foundations and Governance

| Capability | Component | Status |
|------------|-----------|--------|
| Infrastructure as code for every resource (AWS CDK, Python) | All | **Built** |
| Protected-resource tagging convention honoured by automation | Project 1 | **Built** |
| Multi-account structure: Security, Log Archive, workload OUs | Project 6 | *Planned* |
| Organization-wide CloudTrail, GuardDuty, Security Hub, Config | Project 6 | *Planned* |
| SCPs: protect logging, deny unapproved regions, prevent public S3 | Project 6 | *Planned* |
