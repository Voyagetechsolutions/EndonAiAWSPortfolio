# Security Notes: Posture Scanner

See the repository-wide [SECURITY.md](../SECURITY.md) for vulnerability reporting.

## Operating notes

- **Read-only by design.** The scanner's role can only Describe/Get/List the services it
  audits. It has no permission to change any of them; do not add mutating permissions to
  build a "fix" feature. The single auto-remediation in the platform (re-enabling S3 Block
  Public Access) is performed by Project 1's guardrailed response engine, not here.
- **Reports are sensitive.** A posture report is a map of every exposure in the account.
  Reports are stored only in the KMS-encrypted, Object-Lock evidence bucket. Redact
  account IDs before sharing screenshots.
- **Run from the security account.** In the full platform (Project 6) the scanner runs in
  the security account with this stack's read-only role, not from an admin context.

## Using it as a CI gate

`endon-posture-scanner scan --fail-on HIGH` exits non-zero when the account has any
HIGH/CRITICAL misconfiguration. Project 7's pipeline runs it against the environment after
deployment so a change that opens SSH or exposes a bucket fails the build.

## Interpreting the score

The posture score (`100 - Σ severity weights`) is a headline, not a target to game. A high
score with an open CRITICAL finding is still a failing account — read the findings, not
just the number.

## Extending the catalog

Adding a control is one entry in `controls.py` and one check (or a branch in an existing
service check). Add the planted case to `tests/posture_testkit.py` so the benchmark
covers it, and the detection-rate test will enforce it from then on.
