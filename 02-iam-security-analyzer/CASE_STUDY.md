# Case Study: Finding the Admin Who Didn't Look Like One

## Context

A company hands over an AWS account for a security review. IAM has grown for three years:
two dozen users, dozens of roles, home-grown policies. The team believes only two people
have administrator access. The review needs to confirm that — and it needs to be
repeatable, because the account changes every week.

## The problem with reviewing IAM by hand

Reading policies one at a time answers "what does this policy allow". It does not answer
the question that matters: **"who can reach administrator, by any path?"** Three things
hide the real answer:

1. **Effective permissions are scattered.** A user's power is the union of its inline
   policies, its attached managed policies, and every group it belongs to.
2. **Escalation is a combination, not a policy.** `iam:PassRole` on `*` looks innocuous
   until you notice the same principal can create a Lambda function.
3. **Paths hop through roles.** A user with only `sts:AssumeRole` can be an administrator
   if the role it assumes can attach policies to itself.

## The analyzer's run

Pointed at a representative (deliberately vulnerable) copy of the account, read-only:

```text
ENDON AI - IAM SECURITY ASSESSMENT  (111122223333 / us-east-1)
Users scanned: 8   Roles scanned: 5   Policies scanned: 8
Findings: CRITICAL 8   HIGH 8   MEDIUM 3
IAM security score: 0/100

PRIVILEGE-ESCALATION PATHS
  user bob-escalator: direct via AttachUserPolicy
  user carol-passrole: direct via PassRoleToLambda
  user mallory: user:mallory -> role:escalation-target-role then AttachUserPolicy
  role escalation-target-role: direct via AttachUserPolicy
```

The two known admins showed up. So did five principals the team did not think of as
administrators:

| Principal | Looked like | Actually is |
|---|---|---|
| `bob-escalator` | a user who can manage some IAM | can attach `AdministratorAccess` to himself → **admin** |
| `carol-passrole` | a deploy user with `PassRole` | can pass a privileged role to a Lambda she writes → **admin** |
| `dave-wildcard` | "just an `iam:*` helper policy" | every IAM escalation technique at once → **admin** |
| `mallory` | can only assume one role | that role can attach policies to itself → **admin, one hop away** |
| `deployer-role` | internal deploy role | trusts an **external account** with no ExternalId |

`mallory` is the one manual review would have missed. Her policy grants a single action,
`sts:AssumeRole`. The analyzer followed the edge to `escalation-target-role`, confirmed
its trust policy admits her, saw that role can `iam:AttachUserPolicy`, and reported the
full path.

## Before and after

| | Manual review | Endon IAM Analyzer |
|---|---|---|
| Effective permissions | Read policy-by-policy, per principal | Unioned across inline, managed and group policies automatically |
| Escalation paths | Easy to miss combinations and role hops | Every technique + transitive path, with the enabling permissions |
| Confidence | "this looks broad" | Graded: high vs conditional-or-scoped, with the reason |
| Output | Notes in a document | Ranked findings, score, and self-contained HTML report |
| Repeatable | A person, occasionally | A scheduled read-only Lambda, daily, findings on the bus |
| Risk of the tool | — | None to IAM: read-only, enforced by the build |

## What it deliberately did *not* flag

- `erin-readonly` (scoped read-only) — no findings.
- `partner-role` — external trust, but **with** an `sts:ExternalId` condition, the correct
  pattern.
- `break-glass` — administrator, but tagged `endon:protected=true`, so reported at HIGH
  with a note rather than CRITICAL, and never proposed for automatic change.
- `AWSServiceRoleForAutoScaling` — a service-linked role, skipped.

Not crying wolf is what makes the CRITICAL findings worth reading.

## Takeaways

- The dangerous administrator is usually the one who doesn't have `AdministratorAccess`
  attached. Finding them needs effective-permission evaluation and a graph, not a policy
  reader.
- Grading confidence — and staying silent on correctly configured resources — is what
  turns a scanner's output into something a team will actually act on.
- A security tool that can read but never write is one you can schedule and forget; that
  property is worth enforcing in the build, not just intending.
