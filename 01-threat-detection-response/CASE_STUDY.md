# Case Study: Containing a Credential Compromise Before the Attacker Finishes

## Context

A software company runs its production platform on AWS. Its security team is small.
GuardDuty is enabled and findings go to email, where someone reviews them during
working hours.

## The incident

An access key belonging to `ci-deploy-bot`, the CI user that deploys to production,
is exposed in a build log. An attacker picks it up and, over a few minutes:

1. Lists the account's S3 buckets from a hosting-provider IP address.
2. Creates a second access key on the same user, so rotating the leaked key won't lock them out.
3. Opens SSH to `0.0.0.0/0` on the web tier's security group.
4. Stops the account's CloudTrail trail.
5. Removes Block Public Access from `acme-customer-exports`, a bucket of customer data.
6. Starts a cryptocurrency miner on `web-01`.

## Before: manual response

GuardDuty raises findings for the malicious-IP API calls, the stopped trail, the
bucket exposure and the mining traffic. Each one is an email.

To respond, an engineer has to notice the emails, identify the user, find *both*
access keys, work out that the trail was stopped, re-enable Block Public Access, and
isolate `web-01` without terminating it. That last step is the one most likely to be
done wrong under pressure, and doing it wrong destroys the evidence.

**Out of hours, nothing happens until someone reads their email. Until then, the attacker
keeps access, keeps logging off, and keeps customer data exposed.**

## After: Endon AI

Each GuardDuty finding is routed to the response engine through EventBridge. The engine
selects a playbook, checks its guardrails, acts, and records everything.

| Finding | Playbook | What happened | Status |
|---|---|---|---|
| `Recon:IAMUser/MaliciousIPCaller.Custom` | triage | Alert sent. Discovery alone is not contained automatically | MONITORING |
| `UnauthorizedAccess:IAMUser/MaliciousIPCaller.Custom` | compromised-credentials | **Both** keys deactivated; deny-all quarantine policy attached | CONTAINED |
| `Stealth:IAMUser/CloudTrailLoggingDisabled` | logging-tampering | Trail restarted | CONTAINED |
| `Policy:S3/BucketBlockPublicAccessDisabled` | s3-public-exposure | All four Block Public Access settings re-enabled; existing bucket tags kept | CONTAINED |
| `CryptoCurrency:EC2/BitcoinTool.B!DNS` | compromised-ec2 | Instance isolated, termination protection on, left running, forensics requested | CONTAINED |

The security team receives five alerts. Each one says what was detected **and what
has already been done about it**.

## Results

| Measure | Manual process | Endon AI, offline replay | Endon AI, live lab account |
|---|---|---|---|
| Findings handled | 5 emails to triage | 5 incidents, 4 contained automatically | *captured after live run* |
| Finding → containment (engine time) | Depends on who is awake | 0.01 s – 0.41 s per incident | *captured after live run* |
| Evidence preserved | Depends on the responder | Instance running; keys inactive, not deleted; full timeline | *captured after live run* |
| Legitimate access lost | Risk of over-reaction | None: probed instances, recon and break-glass users are not contained | *captured after live run* |

Offline figures come from [`evidence/offline-replay.txt`](evidence/offline-replay.txt),
where AWS is emulated. They measure engine processing, not real-world response time.
Live figures will add GuardDuty's delivery latency and real API latency.

## What was deliberately *not* automated

- **The SSH rule the attacker opened** is not a GuardDuty finding. It is a misconfiguration,
  and it is exactly what the posture scanner (Project 3) is for.
- **Root account activity** alerts humans. Locking root out automatically is too dangerous.
- **Reconnaissance** alerts but does not contain. The false-positive cost is too high.

## Takeaways

- Automated response is valuable only if it is trusted to stay on. The engineering effort
  went into guardrails, severity gates and dry-run, not just the containment calls.
- Isolating an instance correctly takes more than a security group swap: connection
  tracking, Auto Scaling health checks and termination all have to be handled.
- Every automated action produces evidence: tags on the resource, an incident timeline,
  CloudTrail records and an alert. The investigation starts with a complete record.
