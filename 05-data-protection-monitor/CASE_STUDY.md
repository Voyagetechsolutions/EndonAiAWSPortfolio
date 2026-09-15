# Case Study: The Scanner That Can't Leak

## Context

A team wants to know where their secrets are. Not in theory — the actual database
passwords, API tokens and access keys sitting in Lambda environment variables and EC2
launch scripts across the account. The obvious tool is a scanner that finds them and prints
a report.

## The trap in the obvious tool

A scanner that prints the secrets it finds has just created a new copy of every secret — in
its output, its logs, and the report it emails around. If those leak, the scanner *is* the
breach. And if the scanner reads secret values to check them (say, from Secrets Manager),
it now holds broad read access to plaintext secrets — a single compromised function away
from mass exfiltration.

So the real problem isn't detection. It's detecting **without ever holding or emitting a
plaintext secret.**

## The design

Two independent controls make leakage structurally impossible:

**Redaction at the engine boundary.** The detection engine reduces every value it finds to
a few edge characters plus a SHA-256 fingerprint before it leaves the engine:

```text
AWS access key id:  AKI...E5F (sha256:a25a3da7cec3)
GitHub token:       ghp...7r8 (sha256:620e24b63197)
Database password:  pR0...z9x (sha256:3f1fa0c3cde5)
```

The fingerprint is enough to tell two findings apart, and to confirm later that the secret
someone rotated is the one that was flagged — without the finding ever carrying the value.

**No permission to read secret values.** The scanner checks Secrets Manager *rotation* with
`ListSecrets` — metadata only. It has no `GetSecretValue`. There is no code path, and no
IAM permission, by which it could obtain a Secrets Manager plaintext to have to redact.

## The detection, and not crying wolf

The engine pairs signatures (AWS keys, private keys, vendor tokens, DB URLs) with an entropy
path for unknown formats. The entropy path is gated: a high-entropy value is only a secret
if it sits in a secret-*named* variable. That gate is what keeps it from flagging every
build ID and content hash. Placeholders — `changeme`, `${SECRET}`, `<your-key>` — are
dropped. On the demo account the scanner flags the leaky Lambda and instance and stays
silent on the clean ones.

## The one thing it fixes automatically

The scanner reports secrets for a human to rotate — it can't safely guess how. But it shares
one automatic remediation with the rest of the platform, through Amazon Macie: when Macie
classifies sensitive data in a bucket that is *also public*, the monitor raises a CRITICAL
`SensitiveDataPubliclyAccessible` finding, and the Project 1 response engine re-enables
Block Public Access. The classifier finds it; the responder closes it.

## Before and after

| | A naive secret scanner | Endon Data Protection Monitor |
|---|---|---|
| Finds secrets in env vars / user data | Yes | Yes |
| Its output contains the secrets | **Yes — a new exposure** | No — redacted at the engine |
| Reads secret plaintext to check | Often | Never (no `GetSecretValue`) |
| False positives | High (entropy on everything) | Gated by secret-named-variable + placeholders |
| Public sensitive data | Reported | Auto-remediated via Project 1 |

## Takeaways

- A security tool has to model *itself* as part of the threat. For a secrets scanner, "don't
  become the leak" is the primary requirement, not an afterthought.
- Redaction belongs at the point of detection, not the point of display — so nothing
  downstream can get it wrong.
- Removing a capability (the permission to read secret values) is often a stronger control
  than adding one.
