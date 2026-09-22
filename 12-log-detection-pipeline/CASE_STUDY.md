# Case Study: The Attack That Was Made of Ordinary API Calls

## Context

An attacker phishes a developer's access key. Over ten minutes they enumerate the account
(`DescribeInstances`, `ListBuckets`, `ListUsers`…), create a second access key for persistence,
attach `AdministratorAccess` to themselves, stop CloudTrail, delete the GuardDuty detector, open
a security group to the internet, make an exports bucket public, and download two hundred objects
from it. Meanwhile a second IP hammers the console login for the `admin` user.

Not one of those calls is, by itself, an alert. `DescribeInstances` is what every dashboard does.
`GetObject` is what every app does. The attack is invisible unless you look at the *pattern* — the
burst, the sequence, the correlation across the principal's activity. That's the gap between
"we have CloudTrail" and "we detect attacks."

## Two kinds of rule, because attacks have two shapes

**Single-event.** Some things are alarming on their own: the root user making an API call,
`StopLogging`, `AdministratorAccess` being attached, a bucket made public. Each is one predicate
over one CloudTrail record.

**Correlation.** The rest only exist over time, per principal. The engine groups events by who
made them and slides a window: ≥5 `GetObject` in five minutes is exfiltration; ≥4 failed logins is
brute force; ≥8 distinct `Describe`/`List` calls is reconnaissance; the same credentials from two
IPs in ten minutes is stolen-credential use. This is the part a `grep` can't do and a SIEM must.

## Every finding names the adversary's move

Each detection carries a MITRE ATT&CK technique — T1530 for the mass download, T1110 for the brute
force, T1562.008 for the tampered trail. So the output isn't just "SIEM-101 fired"; it's "this
principal is at the Collection stage, exfiltrating data," which is what an analyst or an automated
responder actually prioritises on.

## Proving it — and proving it's quiet

The engine replays the whole kill chain and detects all eleven techniques. Then it replays a
benign day — CI reading a couple of build artifacts, one console login, one IP — and produces
nothing:

```text
Attack log: 11 detections   (CRITICAL 1  HIGH 7  MEDIUM 3)
Benign day: 0 detections
```

Both halves matter. A detector that catches everything by crying wolf is worse than none; the
benign test is what keeps the thresholds honest.

## Portable by design

The single-event detections also ship as **Sigma**, the vendor-neutral rule format that converts
to Splunk, Elastic, and the rest. The engine proves the logic offline and in the platform's
finding format; Sigma carries the same logic into whatever SIEM the company already runs. The work
isn't trapped in one tool.

## Where it sits in the platform

Project 1 is the fast reflex — it reacts to a single GuardDuty finding in seconds. This is the
slower, wider net beneath it: continuous monitoring that finds the multi-step story GuardDuty
might only catch one frame of. A detection here is the same `endon_core.Finding` as everything
else, so it lands in the same SOC (Project 8) and the same ASFF feed — and the same kill chain
that Project 1 contained shows up here as the correlated pattern that explains *why*.

## Takeaways

- The attacks that matter are made of ordinary calls; detection is correlation over time, not
  signature matching.
- Mapping every detection to ATT&CK turns alerts into an intelligible story a responder can act on.
- A benign-traffic test is as important as the attack test — false-positive discipline is what
  makes a detector deployable.
- Expressing rules as Sigma keeps them portable and forces the logic to be clear.
