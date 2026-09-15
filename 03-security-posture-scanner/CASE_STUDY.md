# Case Study: Proving Coverage, Not Claiming It

## Context

"We run a posture scanner" is easy to say. The useful question in an interview — and in
production — is *how much does it actually catch, and how often is it wrong?* This project
answers both with a number, because it is measured against an environment whose flaws are
known in advance.

## The problem posture tools have

A scanner that prints a long list of findings looks impressive and proves nothing. You
cannot tell, from the output alone:

- whether it **missed** anything (false negatives — the dangerous kind), or
- whether half the list is **noise** (false positives that get the tool ignored).

Both are invisible unless you scan something whose correct answer you already know.

## The approach: a benchmark with a manifest

The scanner ships with a deliberately vulnerable environment built through the real AWS
APIs, and a **manifest** recording exactly which control each planted misconfiguration
should trigger — plus a set of intentionally *correct* resources that must produce no
finding at all.

Planted across eight services:

| Service | Planted misconfigurations |
|---|---|
| S3 | a public bucket with no BPA, encryption, TLS, versioning or logging (6 controls) |
| EC2 | SSH+RDP open, all-ports-open SG, unlocked default SG, unencrypted EBS, default encryption off, IMDSv1 (7) |
| RDS | public, unencrypted, no backups (3) |
| CloudTrail | no multi-region trail, no validation, no KMS, not logging (4) |
| KMS | rotation disabled, wildcard key policy (2) |
| IAM | no password policy, root MFA off (2) |
| GuardDuty / Config | both disabled (2) |

Intentionally correct (must **not** be flagged): a fully hardened bucket, a scoped
security group, an encrypted volume, a private + encrypted database, and an external-trust
role gated by an ExternalId.

## The result

```text
DETECTION BENCHMARK
  Planted misconfigurations : 26 controls across 8 services
  Detected                  : 26/26 (100%)
  Missed                    : none
  Additional (baseline)     : none
```

And zero findings on any of the five hardened resources.

The `mallory`-style "gotcha" here is subtler than an escalation path: it is the public
bucket that Block Public Access would have neutralized. The scanner does **not** flag a
public ACL when BPA is fully enabled (that would be a false positive), but **does** flag it
the moment BPA is off — exactly as S3 itself resolves access.

## The end-to-end moment

The public bucket is also where the platform behaves as one system. GuardDuty never emits
an event for "someone made this bucket public" — it is a state, not a behaviour. The
posture scanner finds it, publishes `Posture:S3/BucketPubliclyAccessible` to the Endon
bus, and the Project 1 response engine re-enables Block Public Access automatically. One
tool sees; another closes.

## Before and after

| | A findings dump | Endon Posture Scanner |
|---|---|---|
| Coverage | Unknown | Measured: 26/26 against a manifest, enforced by a test |
| False positives | Unknown | Measured: 0 on five planted clean resources |
| Trust in the tool | "Looks thorough" | "It finds what it should and stays quiet otherwise" |
| Acting on findings | Manual, everything | Public exposure auto-closed by Project 1; the rest ranked and remediable |
| Risk of the tool | — | None to the account: read-only, enforced by the build |

## Takeaways

- A posture scanner's credibility is its **measured** detection and false-positive rate,
  not the length of its output.
- Modelling "public" the way S3 actually does (ACL + policy + Block Public Access
  together) is the difference between a useful finding and noise.
- Detection is a state that must be pulled on a schedule; response is an event. Building
  both, and wiring the one auto-fixable case through to Project 1, is what makes the
  platform coherent rather than a pile of scanners.
