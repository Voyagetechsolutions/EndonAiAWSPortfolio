# Security Notes: IAM Analyzer

See the repository-wide [SECURITY.md](../SECURITY.md) for vulnerability reporting.

## Operating notes

- **Read-only by design.** The analyzer's role can read IAM and generate the credential
  and access-advisor reports. It has no permission to change IAM. Do not add write
  permissions to make a "fix" feature; remediation is a human decision.
- **Reports are sensitive.** An assessment names exploitable escalation paths. Reports are
  stored only in the KMS-encrypted, Object-Lock evidence bucket. If you export one, treat
  it like a penetration-test report: share deliberately, redact account IDs before
  publishing screenshots.
- **Least privilege for the analyzer itself.** Run it from the security account (Project 6)
  with the read-only role in this stack, not from an admin context.

## Using it as a CI gate

`endon-iam-analyzer scan --fail-on CRITICAL` exits non-zero when a change introduces an
administrator-equivalent identity or an escalation path. Project 7's pipeline runs this
against the account after deployment so a risky IAM change fails the build.

## Interpreting confidence

- **high** — the enabling grant is on `Resource:"*"` with no condition. Treat as real.
- **conditional-or-scoped** — the grant is scoped to specific resources or gated by a
  condition. Still worth review: confirm the scope or condition actually prevents
  self-elevation before dismissing it.
