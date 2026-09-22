# Case Study: The Compromise That Showed Up on the Invoice First

## Context

An attacker gets into an AWS account and does what attackers do with cloud compute: they spin up
GPU instances and mine cryptocurrency. To stay quiet, they launch them in `ap-south-1` — a region
the company has never used. They also start pulling data out of an S3 bucket. GuardDuty will
eventually flag the cryptomining, but the *first* thing to move is the bill: compute cost jumps
16× overnight, and data-transfer-out spikes 30×. Finance sees a scary number the next morning and
files a ticket about "unexpected AWS spend." Nobody connects it to security for two days.

The signal was there at hour one. It was just in a dashboard the security team wasn't watching.

## The idea: the bill is a detector

Cost & Usage data is a time series of every dollar, broken down by service, usage type and region.
An attack has a cost shape: cryptomining is a compute spike; exfiltration is an egress spike;
evasion is spend in a region you don't use. So the analyzer builds daily series from the cost rows
and asks, per series, *is the latest day a spike?* — material (above a dollar floor) and well above
the baseline median (a multiple). Compute over the EC2 series, egress over `DataTransfer-Out`, the
budget over the daily total, and a "new region" is one with spend today and none before.

And in the same pass it flags the boring, valuable stuff: spend with no cost-allocation tag, money
paid for idle Elastic IPs. FinOps and security fall out of the same data.

## Why explainable beats clever here

Nobody actions a black-box "anomaly score" on an invoice — finance and security both want to know
*why*. So every finding shows its arithmetic: `compute $683.60 on 2026-09-21 (16x baseline)`,
`$380.00 first appeared in ap-south-1`. That's a sentence an analyst can take to an investigation
and a finance lead can understand. The floors matter too: nothing fires below a dollar threshold,
so cheap variance never cries wolf and the HIGH findings stay worth reading.

## It corroborates the rest of the platform

The killer feature isn't the cost math — it's that a FIN-101 compute spike is now an
`endon_core.Finding`, so it lands in the same SOC (Project 8) as the GuardDuty cryptomining finding
(Project 1) and the CloudTrail detections (Project 12) for the same incident. Three independent
signals — a detector, a log correlation, and the bill — pointing at the same instance, on the same
screen. That's how you go from "unexpected AWS spend" to "confirmed cryptomining in ap-south-1" in
minutes instead of days.

## Proving it

The analyzer runs over a bill with the attack hidden in it and flags all six controls; a
steady-state bill flags none:

```text
Anomalous bill: 6 findings   (HIGH 2  MEDIUM 3  LOW 1)   — compute 16x, egress 30x, new region
Steady-state bill: 0 findings
```

## Takeaways

- The most under-used security signal in AWS is the one finance already watches. Wiring cost into
  the security finding format turns "why is the bill high?" into "we're being cryptomined."
- For cost, explainability isn't optional — a finding has to show the multiple and the dimension or
  nobody acts on it.
- The value compounds through the shared contract: the invoice, the detector and the log now
  corroborate one another in one SOC.
