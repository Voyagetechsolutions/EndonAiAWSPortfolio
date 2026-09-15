# Security Policy

## Reporting a vulnerability

Please report security issues privately through GitHub's **Report a vulnerability**
button (Security → Advisories) rather than opening a public issue. Include the
component, the impact, and steps to reproduce. You will get a response within five
working days.

## Safe use of this repository

Endon AI changes AWS resources automatically. It is built to be safe by default,
and it should be operated that way:

- **Dry-run first.** The response engine deploys in `dry_run` mode. It records what
  it would do without changing anything. Switch to `enforce` only after reviewing
  dry-run incidents from your own environment.
- **Protect break-glass access.** Tag emergency IAM users and roles, and any
  intentionally public buckets, with `endon:protected=true`. The engine will not
  contain them.
- **Attack simulations belong in a lab account.** Scripts under `*/attack-simulation/`
  create deliberately weak resources. They refuse to run unless the current
  credentials match the account ID you pass in, but that check does not replace
  using a dedicated, isolated account.
- **Never commit credentials.** Lab credential files are git-ignored. CI/CD uses
  GitHub OIDC (Project 7), so the repository never needs long-lived AWS keys.
