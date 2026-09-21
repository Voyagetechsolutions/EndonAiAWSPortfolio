# Project 6 · Secure Multi-Account AWS Landing Zone

> Part of the [Endon AI](../README.md) platform · **Status: built and tested** · AWS Organizations + SCPs (CDK)

The governance layer that sits *above* the workload accounts. It defines the organization
structure, a catalog of Service Control Policy guardrails, and the security baseline — and,
crucially, it **proves the guardrails hold** with an SCP simulator: even a full
administrator in a workload account cannot turn off logging or detection, operate in an
unapproved region, make data public, or touch the Endon platform.

---

## The Security Problem

In a single AWS account, whoever has enough IAM permissions can switch off the very
controls that watch them — stop CloudTrail, disable GuardDuty, make a bucket public. IAM
inside an account cannot stop its own administrators. Security that can be disabled by the
people it monitors is not security.

The answer is structural: put the workloads in separate accounts, and put the
non-negotiable controls in **Service Control Policies** attached above those accounts. An
SCP sets the *maximum* permissions for an account — an explicit `Deny` in an SCP cannot be
overridden by any IAM policy in the member account, not even by its root user. This is the
one place a control can hold regardless of what happens inside an account.

This is also where Project 1's residual risk is closed: the response engine could be
disabled by an account administrator. An SCP protecting `Endon*` resources removes that.

**Goal:** an organization where the security controls are guaranteed by construction, and
where that guarantee is demonstrable, not asserted.

## Architecture

```text
Root  [region-allowlist · deny-root-user · prevent-leaving-org · protect-security-logging]
├── Security
│   ├── Security Tooling account   — delegated admin; runs the Endon AI platform
│   └── Log Archive account        — immutable org CloudTrail + Config history (Object Lock)
├── Workloads  [protect-detection-services · prevent-public-s3 · protect-endon-platform]
│   ├── Production
│   └── Development
└── Sandbox   [prevent-public-s3]
```

An account inherits every SCP along its path to the root, so a Production account gets the
Root guardrails *and* the Workloads guardrails.

## The SCP guardrails

Catalog: [`scps/policies.py`](src/endon_landingzone/scps/policies.py). Each is a precise
deny statement; the high-impact ones exempt the security administrator (and, for the
platform's own resources, the deployment pipeline) via `aws:PrincipalArn`, so break-glass
and legitimate operations still work.

| Guardrail | Denies | Exempts |
|---|---|---|
| `protect-security-logging` | Stop/Delete/Update CloudTrail; Stop/Delete Config recorder | security admin |
| `protect-detection-services` | Disable GuardDuty / Security Hub | security admin |
| `region-allowlist` | Any action outside approved regions (global services excepted) | security admin |
| `prevent-public-s3` | Removing account Block Public Access; public bucket ACLs | security admin (BPA) |
| `protect-endon-platform` | Modifying `Endon*` roles, functions and EventBridge rules | security admin + deploy pipeline |
| `prevent-leaving-organization` | `organizations:LeaveOrganization` | — |
| `deny-root-user` | Every action performed by an account's root user | — |

## The guardrail proof (the flagship)

The distinctive piece is [`simulator.py`](src/endon_landingzone/simulator.py): a small SCP
evaluation engine. It takes the SCPs that apply to an account and a candidate request, and
decides whether an explicit deny blocks it — with the condition operators the guardrails
use (`ArnNotLike` on the principal, `StringNotEquals` on the region, `StringEquals` on the
bucket ACL). This turns "we have guardrails" into a demonstrable fact.

```bash
python 06-secure-landing-zone/attack-simulation/guardrail_check.py
```

```text
GUARDRAIL PROOF - a full admin in the Production account
  [DENIED ] Stop CloudTrail logging            <- EndonProtectSecurityLogging
  [DENIED ] Disable GuardDuty                  <- EndonProtectDetectionServices
  [DENIED ] Remove account Block Public Access <- EndonPreventPublicS3
  [DENIED ] Make a bucket public (ACL)         <- EndonPreventPublicS3
  [DENIED ] Operate in an unapproved region    <- EndonRegionAllowlist
  [DENIED ] Modify the Endon response engine   <- EndonProtectPlatform
  [DENIED ] Leave the organization             <- EndonPreventLeavingOrganization

  10/10 dangerous actions blocked by SCP for a workload administrator.
```

And the simulator also proves the guardrails don't get in the way of legitimate work: the
security admin is exempt from the logging/detection denies, the deploy pipeline can still
update `Endon*` resources, global services work despite the region lock, and ordinary
actions are allowed. Those are asserted in [`test_guardrails.py`](tests/test_guardrails.py).

## The security baseline

[`baseline.py`](src/endon_landingzone/baseline.py) records the services the landing zone
turns on org-wide: a multi-region organization CloudTrail to the Log Archive Object Lock
bucket, and AWS Config, GuardDuty, Security Hub and Macie with a delegated administrator in
the Security Tooling account (which runs Endon AI). The organization CloudTrail and the Log
Archive bucket are deployed concretely by the CDK stack.

## Infrastructure

[`infrastructure/landing_zone_stack.py`](infrastructure/landing_zone_stack.py) is deployed
in the **management account**. It creates the OUs, attaches every SCP from the catalog to
the right OUs (`AWS::Organizations::Policy` with `TargetIds`), and stands up the org trail.
The [infrastructure test](../tests/test_landing_zone_infrastructure.py) asserts the OUs, one
policy per catalog SCP with the exact document, and the multi-region validated org trail to
an Object Lock bucket.

```bash
cd 06-secure-landing-zone/infrastructure
cdk deploy -c endon:orgRootId=r-xxxx -c endon:organizationId=o-xxxxxxxxxx
```

## Security Decisions

1. **Controls above the account.** Anything that must survive a compromised or careless
   account administrator lives in an SCP, not in IAM.
2. **Exempt deliberately, and narrowly.** Guardrails exempt only the security admin (and the
   deploy pipeline for platform resources), matched by `aws:PrincipalArn`. Break-glass works;
   nobody else is exempt.
3. **Region and global services.** The region lock uses `NotAction` for global services, so
   IAM, Organizations and CloudFront keep working while everything else is pinned to
   approved regions.
4. **Prove it.** A guardrail nobody has tested is a guess. The simulator makes each control
   a passing assertion, and the same engine drives the evidence.

## Limitations

- **The simulator models SCP *deny* evaluation,** over the default `FullAWSAccess`. It does
  not model SCP allow-lists or IAM policies — because the guardrails are deny-based, which
  is what it evaluates. It is a governance proof, not a full IAM policy simulator (that's
  Project 2).
- **Org bootstrap is partly a management-account operation.** Creating the organization,
  enabling trusted access, and registering delegated administrators for GuardDuty/Security
  Hub/Config/Macie are management-account steps; the baseline records the intent and the CDK
  deploys the OUs, SCPs and org trail.
- **Account creation is out of scope.** The stack models the OU structure; provisioning new
  member accounts (via Account Factory / Control Tower) is a separate concern.

## Lessons Learned

- **The most important control is the one an admin can't turn off.** Moving logging and
  detection protection from IAM (defeatable) to SCPs (not) is the whole point of a landing
  zone, and it's what finally closes Project 1's "an account admin could disable the
  responder" residual risk.
- **A policy document is testable.** Writing SCPs in Python and evaluating them with a
  simulator makes governance a thing with a green checkmark, not a wiki page.
- **Exemptions are where guardrails go wrong.** Getting `aws:PrincipalArn` exemptions
  precise — broad enough for break-glass, narrow enough to mean something — is most of the
  design.

## Run It

```bash
python 06-secure-landing-zone/attack-simulation/guardrail_check.py   # the guardrail proof
pytest 06-secure-landing-zone/tests                                  # tests
endon-landing-zone report                                            # structure + proof
cd 06-secure-landing-zone/infrastructure && cdk deploy -c endon:orgRootId=r-xxxx
```

## Project Layout

```text
06-secure-landing-zone/
├── README.md · CASE_STUDY.md · SECURITY.md
├── architecture/{architecture.md, threat-model.md}
├── src/endon_landingzone/
│   ├── scps/policies.py    the SCP guardrail catalog
│   ├── simulator.py        the SCP evaluation engine (the proof)
│   ├── organization.py     OU tree, accounts, SCP attachment + inheritance
│   ├── baseline.py         org security-services baseline
│   ├── report.py / cli.py
├── infrastructure/{landing_zone_stack.py, app.py, cdk.json}
├── attack-simulation/guardrail_check.py
├── evidence/
└── tests/
```
