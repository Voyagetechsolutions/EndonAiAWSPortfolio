# Case Study: One Number You Can Actually Trust

## Context

A security team has done the work. GuardDuty is on, Security Hub is on, there's an IAM
analyzer, a posture scanner, a data-protection monitor, and an automated responder. On paper,
coverage is excellent. In practice, on any given morning, the on-call engineer opens four
consoles and a spreadsheet and still cannot answer the question their director just asked in
the standup: *"Are we okay right now?"*

The tools produce signal. Nobody has turned the signal into an answer.

## The trap in "just build a dashboard"

The obvious move is a dashboard that pulls everything together and shows a big number. But a
security dashboard has two failure modes that are worse than not having one:

1. **A number nobody trusts.** If the score is a black box — some weighted blend nobody can
   take apart — the security team ignores it, because a number you can't explain is a number
   you can't defend when it's wrong. And it will be wrong sometimes.
2. **A dashboard that is itself a liability.** It aggregates, in one place, the complete map of
   your weaknesses and your response tooling. If it can *act* on the platform, it's a
   privileged foothold for anyone who reaches it. If it serves without authentication, it hands
   that map to anyone who finds the URL.

## The design

The SOC is built around avoiding both traps.

**An explainable score.** The number is a pure function with published weights. Start at 100;
subtract a super-linear weight per open finding (one CRITICAL outranks twenty LOWs); subtract a
fixed penalty for every detective control that is switched off. The board shows the
arithmetic — `-60 findings, -12 blind spots` — so every deducted point traces to a cause. A
security lead can look at a 28 and immediately see *why* it's a 28, and disagree with a weight
rather than distrust the whole thing.

**Blind spots count against you.** The subtlest bug in a findings-based score is that a
disabled detector produces *no findings*, so the board looks greenest exactly when it's most
wrong. So the SOC probes the detectors themselves and feeds the count of disabled ones into the
score — and a detector whose state it cannot confirm is treated as a blind spot, never as
coverage. You cannot claim vision you don't have.

**Read-only by construction.** The console observes; it has no code path that writes, and its
deploy role has read-only access to the data (get/query/scan, never put or delete). A dashboard
that cannot change anything cannot be turned into a weapon by whoever reaches it — that's a
boundary enforced by the infrastructure test, not a promise.

**Authenticated by construction.** Every route sits behind Cognito with MFA. The one thing you
must never do with a map of your own weaknesses is publish it, so the console is never served
unauthenticated.

## Proving it

The whole platform can be seen through the SOC with no AWS account: the demo seeds the stores
with the real output of Projects 1-5 and the board renders from it.

```text
Security Score               28/100   (grade F)
  -60 findings, -12 blind spots
Critical 1   High 2   Medium 2   Low 1
GuardDuty ACTIVE   Security Hub INACTIVE   CloudTrail ACTIVE   AWS Config ACTIVE
09:42  IAM privilege escalation path   iam-risk-review       MONITORING
09:31  Malicious-IP access key         compromised-iam-user  CONTAINED
08:17  Public S3 bucket                s3-public-exposure    CONTAINED
```

You can read the whole story off one screen: a CRITICAL key-compromise that automation already
contained, a public bucket it auto-closed, an escalation path a human still needs to review,
and one detector not yet enabled dragging the score down. That is the answer to "are we okay
right now?" — with the reasoning attached.

## The platform comes together

This is the last component, and it closes the loop the first one opened. Project 1 contains a
threat and writes an incident; Projects 2, 3 and 5 write findings; Project 4 preserves
evidence. The SOC reads all of it through the shared `endon_core` contracts — no bespoke schema,
no direct coupling — and turns eight tools into one view. The platform behaves as one system,
and the SOC is where you finally see it as one.

## Takeaways

- The value of a security dashboard is a number people trust, and trust comes from being able
  to take the number apart. Explainability beat sophistication here.
- A dashboard is a security surface. The decisive choices were subtractive — no write path, no
  unauthenticated route — and they're enforced by tests, not intentions.
- Measuring your own blindness is part of measuring your exposure. A score that ignored disabled
  detectors would be confidently, dangerously wrong.
