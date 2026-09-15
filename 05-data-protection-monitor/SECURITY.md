# Security Notes: Data Protection Monitor

See the repository-wide [SECURITY.md](../SECURITY.md) for vulnerability reporting.

## Operating notes

- **Everything is redacted.** Findings, reports, logs and events carry only redacted tokens
  (`xxx...yyy (sha256:…)`), never plaintext. Do not add code that logs raw values.
- **The monitor never reads secret values.** Its role has `secretsmanager:ListSecrets` but
  not `GetSecretValue`. Do not grant `GetSecretValue` — it would make the monitor an
  exfiltration path. This is enforced by the infrastructure test.
- **Reports are still sensitive.** A report describes *where* your secrets are. It is stored
  only in the KMS-encrypted, Object Lock evidence bucket; restrict the `data-protection/`
  prefix and redact account IDs before sharing.
- **Act on findings by rotating.** The right response to an exposed secret is to rotate it
  and remove it from the exposed location; the monitor deliberately does not do this for you.

## The redaction fingerprint

Each finding carries `sha256:<12 hex>` for the secret. Use it to:

- confirm two findings reference the same secret (same fingerprint), and
- confirm after rotation that the old value is gone (the new value has a different
  fingerprint) — all without the plaintext ever appearing.

## Enabling the Macie path

The sensitive-data classification path needs Amazon Macie enabled (the Project 6 landing
zone enables it org-wide). The event consumer reacts to Macie findings on EventBridge; no
extra configuration is needed beyond the deployed rules.
