# Case Study: The Controls an Administrator Can't Turn Off

## Context

A company runs everything in one AWS account. Security is configured correctly — CloudTrail
on, GuardDuty on, buckets private. Then an engineer with `AdministratorAccess` has their
credentials phished. Within minutes the attacker stops CloudTrail, disables GuardDuty, and
starts exfiltrating from a newly-public bucket. Every control was on. Every control was
turned off by someone who had permission to.

## The problem IAM cannot solve

Inside an account, IAM is the ceiling *and* the floor: an account administrator can grant
themselves anything and disable anything. You cannot use IAM to stop your own administrators
from switching off logging, because the permission to manage logging is itself an IAM
permission they hold. Security that the monitored party can disable is theatre.

## The structural fix

Two moves:

1. **Separate accounts.** Workloads live in their own accounts, under a Workloads OU,
   separate from the Security account that runs the monitoring and the Log Archive account
   that owns the audit trail.
2. **Controls above the account.** The non-negotiable rules live in Service Control
   Policies attached to the OUs. An explicit `Deny` in an SCP cannot be overridden by any
   IAM policy in the member account — not by an administrator, not by the root user.

So the same attacker, with the same stolen `AdministratorAccess`, now hits a wall.

## Proving it

A landing zone diagram is easy to draw and easy to get subtly wrong. So this project
includes an **SCP simulator** and runs the attacker's playbook against the guardrails that
apply to the Production account:

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

Every move in the opening story is now denied — by policy the administrator cannot change.

## And it doesn't break legitimate work

An over-eager guardrail that blocks the security team or the deployment pipeline gets turned
off in week one. So the simulator also proves the exemptions:

- the **security admin** role is still allowed to manage logging and detection (break-glass),
- the **deploy pipeline** can still update `Endon*` resources,
- **global services** (IAM, Organizations) work despite the region lock,
- **ordinary** workload actions are unaffected.

## The platform comes full circle

Project 1's threat model listed one residual risk it couldn't close on its own: *an account
administrator could disable the response engine.* The `protect-endon-platform` SCP closes
it — the responder and its EventBridge rules can only be changed by the deploy pipeline.
The landing zone is what makes the automated responder trustworthy in a real org.

## Takeaways

- The decisive security control is the one the monitored party cannot disable. That requires
  moving it out of IAM and into the organization.
- Writing SCPs in code and evaluating them with a simulator turns governance from a claim
  into a test — the same shift the rest of this portfolio makes everywhere.
- Guardrails live or die by their exemptions. The engineering is in making them precise.
