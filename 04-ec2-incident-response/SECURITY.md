# Security Notes: EC2 Forensics

See the repository-wide [SECURITY.md](../SECURITY.md) for vulnerability reporting.

## Operating notes

- **Preserve-only by design.** The forensics role can inspect instances, snapshot volumes,
  read the console and CloudTrail, run read-only SSM commands, and write evidence. It has
  no permission to stop, terminate or delete the instance, its volumes, or the snapshots
  and evidence it produces. Do not add such permissions.
- **Evidence is sensitive.** Snapshots and console output can contain secrets and personal
  data. Evidence is stored only in the KMS-encrypted, Object Lock evidence bucket. Restrict
  who can read the `forensics/` prefix.
- **Legal holds.** The evidence bucket uses Object Lock in GOVERNANCE mode (90 days). For a
  formal legal hold, apply COMPLIANCE-mode retention or a legal hold to the specific case
  prefix — GOVERNANCE can be bypassed by a principal with `s3:BypassGovernanceRetention`
  (which this role is denied, and which should be denied org-wide via SCP in Project 6).

## Live response (volatile memory)

By default a compromised instance is fully isolated and volatile collection is skipped.
To enable it, the quarantine security group must allow **egress to the SSM VPC endpoints
only** (`com.amazonaws.<region>.ssm`, `.ssmmessages`, `.ec2messages`). This is a deliberate
reduction in isolation; make it a conscious choice per incident, not a default.

## Reversing / cleaning up

Evidence snapshots are tagged `endon:evidence=true` with the incident id. They are retained
deliberately; delete them only when the investigation is closed and any legal hold is
lifted, and record who did so.
