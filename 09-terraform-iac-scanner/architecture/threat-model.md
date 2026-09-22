# Threat Model: Terraform IaC Scanner

## Scope

A static analyzer over a Terraform plan, and the CI gate it drives. Its job is to stop insecure
infrastructure from being *created* — to move a class of misconfiguration from "found in
production" to "blocked in the pull request." The scanner is read-only and credential-free; the
threats are about what it must catch and how it could be bypassed.

## Assets

| Asset | Why it matters |
|---|---|
| The account's future security posture | Every insecure resource created is a live exposure |
| The CI gate's integrity | If it can be silently skipped or fooled, it protects nothing |
| The audit trail (CloudTrail) | A trail that's created single-region/unencrypted has gaps from day one |

## Attackers / failure sources

| Source | Position | Concern |
|---|---|---|
| Careless / hurried engineer | Opens a PR with insecure Terraform | The common case — a public bucket, an open SG, an unencrypted DB |
| Insider adding a backdoor | Can write Terraform | An admin-wildcard policy, an unscoped `PassRole`, a public RDS |
| A drifted default | Provider default is insecure | Rotation off, IMDSv1 allowed unless explicitly hardened |

## Threats and controls

| # | Threat | Control | Proven by |
|---|---|---|---|
| 1 | A public S3 bucket is created | TF-S3-001 (public ACL or BPA disabled) | benchmark: fires on insecure plan |
| 2 | Data at rest is unencrypted (S3/EBS/RDS) | TF-S3-002, TF-EBS-001, TF-RDS-001 | benchmark |
| 3 | SSH/RDP or any port is open to the internet | TF-EC2-001 / 002 | benchmark + `test_rules` |
| 4 | Instance credentials stealable via IMDSv1/SSRF | TF-EC2-003 (`http_tokens` must be `required`) | `test_rules` |
| 5 | A publicly-reachable database | TF-RDS-002 | benchmark |
| 6 | An administrator-equivalent policy is provisioned | TF-IAM-001 (reuses Project 2) | `test_iam_admin...` |
| 7 | A privilege-escalation `PassRole` is provisioned | TF-IAM-002 (reuses Project 2) | `test_iam_admin...` |
| 8 | The audit trail is incomplete/unencrypted | TF-LOG-001 | benchmark |
| 9 | The scanner passes an insecure change (false negative) | benchmark asserts all 13 controls fire | `test_every_control_fires...` |
| 10 | The scanner blocks a safe change (false positive) | secure plan must produce nothing | `test_the_secure_plan_produces_no_findings` |

## Ways the gate could be defeated (and the answer)

| Bypass | Mitigation |
|---|---|
| Scan one plan, apply a different one | Operating rule: `plan -out`, scan that plan's JSON, `apply` that same plan file |
| Lower `--fail-on` to hide findings | A visible, reviewable change in CI config — not a silent drop; keep the threshold in code review |
| Put the insecure config where the plan can't show it | Cross-resource/"known after apply" gaps are covered by the running-account scanner (Project 3) — defence in depth |
| Skip the gate entirely | The gate is a required check in the Project 7 pipeline, before `apply` |

## Residual risks

| Risk | Why it remains | Treatment |
|---|---|---|
| 13 controls is not every misconfiguration | Curated catalog, not exhaustive | Add controls over time; pair with Project 3 in the live account |
| Cross-resource posture (separate policy/ACL resources) | Rules are per-resource on plan attributes | Project 3 evaluates the resolved live state |
| Non-AWS providers | Rules target `aws_*` | Out of scope by design |
