# Case Study: Catching the Public Bucket in the Pull Request

## Context

A team ships infrastructure with Terraform. An engineer adds an S3 bucket for "temporary"
exports, sets `acl = "public-read"` to make sharing easy, and — because a separate ticket
disabled Block Public Access "to unblock a demo" — the plan quietly creates a world-readable
bucket. The PR is approved (the diff looks small), `terraform apply` runs in CI, and the
bucket is public. Nobody notices until Project 3's posture scanner flags it in production, or
until it shows up in someone else's breach report.

Every step of that story happened *after* the insecure code was written. The cheapest place to
stop it was the pull request.

## The idea: scan what Terraform will create

`terraform plan` already computes exactly what `apply` will do, and `terraform show -json`
emits it as plain JSON — variables resolved, defaults applied, computed values filled in. So
the scanner reads the plan, not the raw HCL, and asks one question per resource: *is this
insecure?* A public ACL, a `0.0.0.0/0` security group, an unencrypted volume, an
admin-wildcard IAM policy — each is a small predicate over the resource's planned attributes.

Because it runs on the plan, it sees the real values. `acl = var.bucket_acl` tells a raw-HCL
linter nothing; the plan says `acl = "public-read"`, and the finding is unambiguous.

## Reusing the platform's brain

The most interesting rules are the IAM ones. Rather than re-implement "what makes a policy
dangerous," the scanner lifts the policy JSON straight out of the plan and runs it through
**Project 2's** evaluator — the same deny-wins, wildcard-aware `PermissionSet` that grades live
accounts. An `Action:"*" Resource:"*"` policy is administrator-equivalent whether it's attached
in production or still a string in a plan, and now it's judged by the same code in both places.

## Proving it, not claiming it

A scanner you can't measure is a scanner you can't trust. So the project ships a
deliberately-insecure Terraform stack that trips all 13 controls and a hardened twin that
trips none, and a test asserts exactly that:

```text
15 findings on the insecure plan   (CRITICAL 4  HIGH 7  MEDIUM 4)
 0 findings on the hardened plan
Gate (fail-on HIGH): FAILED — 11 blocking
```

Detection is a passing test; a false positive is a failing one.

## Closing the loop with the pipeline

The scanner's CLI exits non-zero on any blocking finding, so it drops straight into
**Project 7's** keyless pipeline as a pre-`apply` gate — the natural third sibling of the IAM
gate (Project 2) and the posture gate (Project 3). Now the pipeline that deploys the platform
refuses three ways: an over-permissioned identity, a live misconfiguration, *and* an insecure
change still in its plan. The public bucket never gets created, because the CI check that would
have created it fails first.

## And it writes Terraform, not just reads it

To make the point that this isn't only an analyzer, the project re-provisions the Endon
platform baseline — KMS key, incident/finding tables, Object Lock evidence bucket — as an
idiomatic Terraform module that passes its own scanner. The guardrail and the infrastructure it
guards are written to the same standard.

## Takeaways

- The same misconfiguration is a failed CI check here and an incident in a running account. The
  entire value is *when* you catch it.
- Scanning the resolved plan, not the source HCL, is what makes the findings real.
- Delegating "is this admin?" to the existing IAM engine kept one definition of danger across
  the whole platform — live accounts and Terraform plans alike.
