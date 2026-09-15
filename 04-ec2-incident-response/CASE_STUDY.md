# Case Study: Containment That Preserves Evidence

## Context

A GuardDuty finding fires: an EC2 instance in production is querying a cryptocurrency
mining pool. The Project 1 response engine isolates it in seconds. Now the harder question:
*what actually happened, and can we prove it?*

## The problem with the obvious response

The instinct — terminate the instance — is the worst thing you can do for an
investigation. Terminating destroys:

- **memory**: the running malware, its configuration, the attacker's live sessions;
- **process and network state**: what was running, what it was talking to;
- **disk**: unless it was snapshotted first;
- **the timeline**: without a record, you can't reconstruct the order of events.

And collecting evidence by hand is slow and undefensible. Which volumes did you snapshot?
What time? Who touched the instance? Was the evidence altered afterwards? Without answers,
the evidence is worthless in an incident review — or a courtroom.

## The automated response

The moment Project 1 publishes `Endon Forensics Requested`, the forensics engine collects
evidence in the correct forensic order and records everything:

```text
COLLECTION TIMELINE
  +0.000s  Forensics requested - CryptoCurrency:EC2/BitcoinTool.B!DNS
  +0.793s  Isolation verified - contained
  +1.012s  volatile-data: SKIPPED   (host isolated; not SSM-reachable)
  +1.030s  instance-metadata: COLLECTED
  +1.042s  console-output: COLLECTED
  +1.324s  ebs-snapshots: COLLECTED
```

Every artifact is SHA-256 hashed as it's stored, and a chain-of-custody manifest ties them
together:

```text
CHAIN OF CUSTODY
  Case status     : COLLECTED
  Collector       : arn:aws:sts::…:assumed-role/EndonForensics/…
  EBS snapshots   : snap-5d3318d2025e01c33
  Manifest sha256 : 7f1de756ac662284a13286a2e5a911ff…
  Object Lock     : GOVERNANCE until 2026-12-14
```

## The two decisions that matter

**Isolate, never terminate.** The instance stays running, isolated. Its memory and disk are
preserved. The engine has *no permission* to stop or terminate it — an explicit IAM deny
guarantees it, even if the code had a bug.

**The honest gap.** Volatile memory was *not* collected, and the case says so, with the
reason: a fully isolated host can't reach SSM. This is the real forensic trade-off between
isolation and live response, made visible in the evidence rather than papered over. To
collect memory, the quarantine security group would need a narrow egress path to the SSM
endpoints — a deliberate choice, not a default.

## Before and after

| | Manual forensics | Endon EC2 Forensics |
|---|---|---|
| Trigger | A human notices, eventually | Automatic, on isolation |
| Order | Ad hoc | Order of volatility, enforced |
| Integrity | Hoped for | SHA-256 per artifact, at collection time |
| Immutability | None | S3 Object Lock (WORM), can't be altered or deleted |
| Chain of custody | Notes, maybe | A hashed, timestamped, attributed manifest |
| Risk to evidence | High (fat-finger a terminate) | None — the role literally cannot terminate |

## Takeaways

- The most important forensic control is a *negative* capability: the collector's inability
  to destroy what it's preserving.
- Evidence integrity is established when you collect, not when you report. Hash on the way
  into a write-once store.
- Being honest about what you *couldn't* collect — and why — is part of a defensible
  investigation, not a weakness in the tool.
