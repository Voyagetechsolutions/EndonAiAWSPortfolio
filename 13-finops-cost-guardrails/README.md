# Project 13 · FinOps + Security-Cost Guardrails

> Part of the [Endon AI](../README.md) platform · **Status: built and tested** · Cost & Usage + Python

The bill is a detector. This analyzes AWS cost data for two things at once: **waste** (untagged
spend, idle resources, a budget-busting day) and **security-relevant cost anomalies** — a sudden
compute spike (what cryptomining looks like on the invoice), a data-transfer-out surge (what
exfiltration looks like), spend in a region you never use. FinOps and security, from the same
data — a pairing most tools keep apart, and a genuine differentiator.

---

## The Security Problem

When an attacker mines cryptocurrency in a compromised account, the loudest early signal is often
not a GuardDuty finding — it's the invoice. Compute cost jumps 10× overnight in a region nobody
uses. When they exfiltrate data, data-transfer-out spikes. These show up in Cost Explorer *hours
before* anyone reads the detection console, and every finance team is already watching the number
go up — they just don't know it's a security event. Meanwhile the same data is full of ordinary
waste that a security team can help fix.

**Goal:** treat a cost spike as a compromise signal, flag waste in the same pass, emit both as the
platform's finding format so a cryptomining spike lands next to the GuardDuty finding it
corroborates — and prove it against a bill with a planted attack.

## What it checks

[`controls.py`](src/endon_finops/controls.py) is the catalog (6 controls);
[`analyzers.py`](src/endon_finops/analyzers.py) is the logic.

**FinOps (waste & governance)**

| Control | Flags | Severity |
|---|---|---|
| FIN-001 | Significant untagged spend (no cost-allocation tag) | MEDIUM |
| FIN-002 | Paying for idle resources (e.g. idle Elastic IPs) | LOW |
| FIN-003 | A daily total cost anomaly (budget) | MEDIUM |

**Security-cost (a cost spike as a compromise signal)**

| Control | Flags | ATT&CK-ish | Severity |
|---|---|---|---|
| FIN-101 | Compute cost spike — possible cryptomining | Resource hijacking | HIGH |
| FIN-102 | Data-transfer-out spike — possible exfiltration | Exfiltration | HIGH |
| FIN-103 | Spend in a previously-unused region | Defense evasion | MEDIUM |

## How it finds a spike

The analyzers build per-key **daily time series** from the cost rows and compare the latest day to
the baseline of the prior days. A spike ([`detect_spike`](src/endon_finops/costs.py)) needs the
latest day to be both *material* (above a dollar floor, so cheap noise never fires) and *well
above* the baseline median (a multiple, so normal variance never fires). Compute cost runs this
over the EC2 series; egress over the `DataTransfer-Out` series; the budget check over the daily
total; and a region is "new" if it has spend on the latest day and none before. It's simple,
explainable, and testable — no black-box anomaly model.

## The proof (the flagship)

The analyzer runs over a bill where a compromise is hiding in the numbers — a p3 GPU instance
spun up in `ap-south-1` (cryptomining), a 30× data-transfer-out surge (exfiltration) — alongside
ordinary waste. It flags all six controls; a steady-state bill flags none.

```bash
python 13-finops-cost-guardrails/attack-simulation/analyze_cryptomining_spike.py
```

```text
>> [HIGH  ] FIN-101  EC2               compute $683.60 on 2026-09-21 (16x baseline)
>> [HIGH  ] FIN-102  DataTransfer-Out  egress $300.00 on 2026-09-21 (30x baseline)
   [MEDIUM] FIN-103  ap-south-1        $380.00 first appeared in ap-south-1
   [MEDIUM] FIN-003  total             $1011.60 vs $81.60 baseline
   [MEDIUM] FIN-001  account           $64.00 of spend has no 'team' tag
   [LOW   ] FIN-002  ElasticIP:IdleAddress   $28.80 paid for idle Elastic IPs
  6 finding(s)   HIGH 2  MEDIUM 3  LOW 1   Gate (fail-on HIGH): FAILED — 2 blocking

Steady-state bill: 0 finding(s) — gate PASSED
```

## How it connects to the platform

| Direction | Contract |
|---|---|
| Reads | A Cost Explorer / CUR export (daily line items with service, usage type, region, tags) |
| Emits | `endon_core.Finding` (`FinOps:<Area>/<Name>`) into the bus, stores, SOC and ASFF |
| Corroborates | A FIN-101 compute spike is the invoice-side view of Project 1's cryptomining incident and Project 12's detections |

## Security Decisions

1. **The bill is a security sensor.** Compute and egress spikes are treated as HIGH — they can be
   the earliest sign of resource hijacking or exfiltration.
2. **Explainable over clever.** A material-and-multiple spike test, not an opaque model, so every
   finding shows its arithmetic (`$683.60 vs $81.60`, `16x`).
3. **Floors kill the noise.** Nothing fires below a dollar threshold, so cheap variance stays
   quiet and the HIGH findings stay meaningful.
4. **FinOps and security share the data.** One pass yields both waste to cut and attacks to catch.

## Limitations

- **Cost data lags and is coarse.** Cost Explorer/CUR update on a delay and aggregate; this is an
  early *corroborating* signal, not a real-time detector — pair it with Project 12 and GuardDuty.
- **A spike is a signal, not proof.** A legitimate load test or a big batch job also spikes
  compute; the finding says "investigate," and names the day, region and multiple to make that
  fast.
- **Simple statistics.** Median-and-multiple is deliberately explainable; seasonal/holiday-aware
  baselining is a future refinement.

## Lessons Learned

- **Follow the money.** The most under-used security signal in AWS is the one finance already
  watches — cost. Wiring it into the same finding format was the whole idea.
- **Explainability wins for cost.** Nobody actions a black-box "anomaly score" on a bill; a
  finding that says "16× the baseline, in a region you don't use" gets investigated.
- **The shared contract, one more time.** A cost anomaly, a GuardDuty finding and a CloudTrail
  detection for the same incident now sit side by side in the SOC.

## Run It

```bash
python 13-finops-cost-guardrails/attack-simulation/analyze_cryptomining_spike.py   # analysis + proof
pytest 13-finops-cost-guardrails/tests                                             # tests (7)
endon-finops analyze 13-finops-cost-guardrails/fixtures/anomalous.json --fail-on HIGH
```

## Project Layout

```text
13-finops-cost-guardrails/
├── README.md · CASE_STUDY.md · SECURITY.md
├── architecture/{architecture.md, threat-model.md}
├── src/endon_finops/
│   ├── costs.py       load cost rows + build daily series + the spike primitive
│   ├── controls.py    the catalog (3 FinOps + 3 security-cost)
│   ├── analyzers.py   one analyzer per control
│   ├── engine.py      analyzers -> endon_core Findings
│   └── report.py / cli.py
├── fixtures/          anomalous + clean cost exports
├── attack-simulation/analyze_cryptomining_spike.py
├── evidence/
└── tests/
```
