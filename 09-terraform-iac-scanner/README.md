# Project 9 · Terraform IaC Security Scanner

> Part of the [Endon AI](../README.md) platform · **Status: built and tested** · Terraform + Python

Shift security *left*, into the pull request. This scans a Terraform **plan** — what Terraform
is about to create — and flags insecure infrastructure before `apply` ever runs: public S3
buckets, `0.0.0.0/0` security groups, unencrypted EBS/RDS, admin-wildcard IAM policies, and
more. It's a small, honest [Checkov](https://www.checkov.io/)/[tfsec](https://aquasecurity.github.io/tfsec/),
built to plug into the same platform (and the same Project 7 pipeline) as everything else.

---

## The Security Problem

Project 3 finds a public bucket *in a running account* — after it exists, after it may already
have leaked. By then the fix is incident response. The cheaper place to catch it is the pull
request that introduced it: the Terraform that will *create* the public bucket is right there,
reviewable, before anything is provisioned. Most misconfigurations are born in code. Catching
them in code is the difference between a failed CI check and a 2 a.m. page.

**Goal:** a scanner that reads a Terraform plan, flags the insecure resources with the same
severity model and finding format as the rest of the platform, and fails a CI gate so an
insecure change can't be applied.

## Why scan the *plan*, not the HCL

The scanner reads the JSON that `terraform show -json plan.out` emits, not raw `.tf`. That is
the right layer:

- **Everything is resolved.** Variables, defaults, `locals`, module inputs and computed values
  are already applied, so a rule sees the *real* value of an attribute — not `var.encrypted`.
- **It's exactly what will be created.** The plan is Terraform's own answer to "what will
  `apply` do?", so a finding maps to a resource that is actually about to exist.
- **It needs no parser.** Plan output is plain JSON — [`plan.py`](src/endon_tfscan/plan.py)
  reads it with the standard library, and the same fixtures drive the tests with no Terraform
  binary in the loop.

## What it checks

[`controls.py`](src/endon_tfscan/controls.py) is the catalog (13 controls); the detection for
each lives in [`rules.py`](src/endon_tfscan/rules.py) as one small predicate.

| Control | Flags | Severity |
|---|---|---|
| TF-S3-001 | Public bucket (public ACL, or Block Public Access disabled) | CRITICAL |
| TF-S3-002 / 003 | No server-side encryption / no versioning | HIGH / MEDIUM |
| TF-EC2-001 / 002 | SSH/RDP open to `0.0.0.0/0` / any open ingress | HIGH / MEDIUM |
| TF-EC2-003 | IMDSv2 not enforced (`http_tokens != required`) | MEDIUM |
| TF-EBS-001 | Unencrypted EBS volume | HIGH |
| TF-RDS-001 / 002 | Unencrypted RDS / publicly accessible RDS | HIGH / CRITICAL |
| TF-IAM-001 | Administrator-equivalent policy (`Action:* Resource:*`) | CRITICAL |
| TF-IAM-002 | Unscoped `iam:PassRole` (a privilege-escalation path) | HIGH |
| TF-KMS-001 | KMS key rotation disabled | MEDIUM |
| TF-LOG-001 | CloudTrail single-region or unencrypted | HIGH |

**The IAM rules reuse Project 2.** `TF-IAM-001` and `TF-IAM-002` parse the policy JSON out of
the plan and run it through the *same* `PermissionSet`/`grants_admin` evaluator that powers the
live IAM analyzer — so "what counts as admin" is decided in one place, whether the policy is
live in an account or still a string in a plan.

## The proof (the flagship)

Like Project 3's detection benchmark, coverage is a measured number, not a claim.
[`terraform/examples/insecure`](terraform/examples/insecure/main.tf) is a real stack that
trips every control; [`secure`](terraform/examples/secure/main.tf) is its hardened twin. The
[benchmark test](tests/test_scanner_benchmark.py) asserts **every control fires on the
insecure plan and none fires on the secure one**.

```bash
python 09-terraform-iac-scanner/attack-simulation/scan_insecure_stack.py
```

```text
ENDON AI - TERRAFORM IaC SECURITY SCAN
>> [CRITICAL] TF-IAM-001  aws_iam_policy.admin       IAM policy grants administrator-equivalent access
>> [CRITICAL] TF-RDS-002  aws_db_instance.db         RDS instance is publicly accessible
>> [CRITICAL] TF-S3-001   aws_s3_bucket.public       S3 bucket is exposed publicly
   ... 12 more ...
  15 finding(s)   CRITICAL 4  HIGH 7  MEDIUM 4
  Gate (fail-on HIGH): FAILED — 11 blocking

Hardened plan: 0 finding(s) — gate PASSED
```

## The CI gate

[`cli.py`](src/endon_tfscan/cli.py) is the gate: `endon-tfscan scan plan.json --fail-on HIGH`
prints the board (or `--json`) and **exits non-zero** on any blocking finding. It slots into
the Project 7 pipeline right before `terraform apply` — the natural pre-apply sibling of the
IAM and posture gates:

```yaml
- run: terraform plan -out plan.out
- run: terraform show -json plan.out > plan.json
- run: endon-tfscan scan plan.json --fail-on HIGH   # blocks the apply on an insecure change
- run: terraform apply plan.out
```

## Real Terraform, too

This project doesn't just *scan* Terraform — it *writes* it.
[`terraform/platform`](terraform/platform/main.tf) re-provisions the Endon platform baseline
(the customer-managed KMS key, the incident/finding DynamoDB tables, the Object Lock evidence
bucket) as an idiomatic Terraform module, mirroring the CDK `PlatformStack`. It is written to
pass the scanner cleanly — the infrastructure and the guardrail that checks it agree.

## How it connects to the platform

| Direction | Contract |
|---|---|
| Emits | `endon_core.Finding` (type `IaC:<Service>/<Name>`), so results reach the bus, stores, SOC and ASFF like any producer |
| Reuses | Project 2's `PermissionSet`/`PolicyDocument` for the IAM policy rules |
| Gates | The Project 7 pipeline, pre-`apply`, next to the IAM (P2) and posture (P3) gates |
| Complements | Project 3 finds the issue in a *running* account; this finds it in the *plan* |

## Security Decisions

1. **Scan the plan, not the HCL.** Resolved values, exactly what will be created, no bespoke
   parser — and hermetic tests.
2. **One meaning of "admin".** IAM grading is delegated to Project 2, not re-implemented, so a
   wildcard policy is judged the same everywhere.
3. **Prove coverage.** An insecure/secure benchmark makes detection a passing test and false
   positives a failing one.
4. **Gate, don't nag.** A severity-thresholded non-zero exit blocks the apply; below the
   threshold it reports and moves on.

## Limitations

- **It evaluates the plan's resource attributes,** so a rule needs the attribute to be present
  in the plan. Cross-resource reasoning (e.g. a bucket policy in a *separate* resource) and
  provider-computed "known after apply" values are out of scope — it complements, not replaces,
  a full policy engine and a running-account scanner (Project 3).
- **13 controls is a curated set,** not exhaustive coverage of every AWS resource.
- **AWS provider only.** The plan format is provider-agnostic; the rules target `aws_*`.

## Lessons Learned

- **Left is cheaper than right.** The same public-bucket issue is a failed CI check here and an
  incident in Project 3 — catching it in the plan is strictly cheaper.
- **Reuse beats re-implementation.** Grading IAM policies by importing Project 2 kept the
  definition of "admin" in one place and made the IAM rules trivially correct.
- **The plan JSON is an underrated interface.** Testing against committed `terraform show -json`
  output gave real coverage with zero Terraform in the test loop.

## Run It

```bash
python 09-terraform-iac-scanner/attack-simulation/scan_insecure_stack.py   # the scan + proof
pytest 09-terraform-iac-scanner/tests                                      # tests (19)
endon-tfscan scan 09-terraform-iac-scanner/terraform/plans/insecure.plan.json --fail-on HIGH
```

## Project Layout

```text
09-terraform-iac-scanner/
├── README.md · CASE_STUDY.md · SECURITY.md
├── architecture/{architecture.md, threat-model.md}
├── src/endon_tfscan/
│   ├── plan.py        parse `terraform show -json` into resources
│   ├── controls.py    the IaC control catalog (13)
│   ├── rules.py       one predicate per control (IAM rules reuse Project 2)
│   ├── scanner.py     rules -> endon_core Findings
│   ├── report.py      console/JSON + the CI gate result
│   └── cli.py         endon-tfscan scan <plan.json> --fail-on
├── terraform/
│   ├── platform/      the Endon baseline, in Terraform
│   ├── examples/{insecure,secure}/
│   └── plans/         committed `terraform show -json` fixtures
├── attack-simulation/scan_insecure_stack.py
├── evidence/
└── tests/
```
