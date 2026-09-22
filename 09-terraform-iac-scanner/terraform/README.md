# Terraform

Real Terraform that this project both **provisions** and **scans**.

```text
terraform/
├── platform/          the Endon platform baseline in Terraform (KMS, DynamoDB, evidence bucket)
├── examples/insecure/ a deliberately insecure stack — the scanner's target
├── examples/secure/   the hardened counterpart — the scanner reports nothing
└── plans/             committed `terraform show -json` output, so the scanner's tests need no Terraform binary
```

## Scanning a plan

```bash
cd examples/insecure
terraform init
terraform plan -out plan.out
terraform show -json plan.out > ../../plans/insecure.plan.json
endon-tfscan scan ../../plans/insecure.plan.json --fail-on HIGH   # exits non-zero
```

The committed `plans/*.json` are exactly this output, so `pytest` runs the scanner against a
real plan with no Terraform installed.

## Deploying the platform baseline

```bash
cd platform
terraform init
terraform plan  -var evidence_bucket_name=endon-evidence-<account-id>
# endon-tfscan scan <this plan> --fail-on HIGH   # gate it, then:
terraform apply -var evidence_bucket_name=endon-evidence-<account-id>
```

The baseline is written to pass the scanner cleanly — the infrastructure and the guardrail
that checks it are the same story.
