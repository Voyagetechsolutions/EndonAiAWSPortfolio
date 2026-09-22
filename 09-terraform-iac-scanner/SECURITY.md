# Security Notes: Terraform IaC Scanner

See the repository-wide [SECURITY.md](../SECURITY.md) for vulnerability reporting.

## Operating notes

- **The scanner only reads.** It parses a plan JSON file and emits findings; it never calls
  AWS, never touches state, and needs no credentials. Run it anywhere, including untrusted CI.
- **Gate on the plan, apply the plan.** Generate the plan once (`terraform plan -out plan.out`),
  scan `terraform show -json plan.out`, then `terraform apply plan.out` — applying the *same*
  plan you scanned. Don't scan one plan and apply a freshly-generated other; they can differ.
- **Pick the threshold deliberately.** `--fail-on HIGH` blocks HIGH and CRITICAL. Loosening it
  to only CRITICAL, or to a warn-only advisory step, is a real risk decision — make it in the
  open, not by quietly dropping the gate.
- **It is a floor, not a ceiling.** Passing `endon-tfscan` means none of *these 13 controls*
  fired. Keep running the posture scanner (Project 3) against the live account and the IAM
  analyzer (Project 2) — defence in depth, not a single gate.

## Scope and blind spots

- **Plan attributes only.** A rule can only see what the plan contains. Values marked "known
  after apply" and security posture that spans multiple resources (a bucket policy in a separate
  `aws_s3_bucket_policy`, for instance) are not fully evaluated here — that is what the
  running-account scanner is for.
- **AWS provider.** Rules target `aws_*` resource types. Other providers pass through unflagged.
- **No secret handling.** The scanner reads infrastructure config, not data; it does not inspect
  or emit secret values (that is Project 5's job, with its own guarantees).

## Using it in CI

Run the scan as a required check *before* `terraform apply`, on the exact plan you will apply:

```bash
terraform plan -out plan.out
terraform show -json plan.out > plan.json
endon-tfscan scan plan.json --fail-on HIGH
terraform apply plan.out
```

An insecure change then cannot be merged or applied without someone consciously lowering the
gate.
