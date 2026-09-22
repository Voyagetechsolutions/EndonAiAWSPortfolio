# Project 12 · Cloud Log Detection Pipeline (SIEM-lite)

> Part of the [Endon AI](../README.md) platform · **Status: built and tested** · CloudTrail + Sigma + Python

Detection engineering at data scale. Project 1 reacts to individual GuardDuty findings; this is
the layer beneath it — a **SIEM-style detection engine** that reads the raw CloudTrail stream and
finds the attacks that only show up as a *pattern*: a burst of `GetObject` (exfiltration),
repeated failed logins (brute force), a scan of `Describe`/`List` calls (reconnaissance), the same
credentials from two IPs. Every detection carries a MITRE ATT&CK technique, and the single-event
rules ship as portable **Sigma** so they run in any SIEM.

---

## The Security Problem

GuardDuty is great at what it flags — but plenty of attacks are made of ordinary API calls that
are only suspicious *together*. One `GetObject` is a download; two hundred in five minutes is
exfiltration. One failed console login is a typo; forty is a brute-force. The signal isn't in any
single record — it's in the correlation across a principal's activity over time. That's
continuous monitoring, and it's exactly the "detection at scale" a modern SOC lives on.

**Goal:** ingest CloudTrail, run single-event *and* windowed-correlation detections mapped to
ATT&CK, emit the results as the platform's finding format, and prove coverage against a
known attack — with the rules also expressed as Sigma so they aren't locked to this engine.

## Two kinds of detection

[`detections.py`](src/endon_siem/detections.py) is the catalog (11 detections); the engine is
[`engine.py`](src/endon_siem/engine.py).

**Single-event** — one CloudTrail record is enough:

| ID | Detects | ATT&CK | Severity |
|---|---|---|---|
| SIEM-001 | Root account activity | T1078.004 | CRITICAL |
| SIEM-002 | CloudTrail `StopLogging`/`DeleteTrail` | T1562.008 | HIGH |
| SIEM-003 | GuardDuty/Config/Security Hub disabled | T1562.001 | HIGH |
| SIEM-005 | `AdministratorAccess` attached | T1098 | HIGH |
| SIEM-006 | S3 bucket made public | T1530 | HIGH |
| SIEM-004 / 007 | Access key created / SG opened to `0.0.0.0/0` | T1098.001 / T1562.007 | MEDIUM |

**Correlation** — a time window over one principal's activity, where a SIEM earns its keep:

| ID | Detects | Window | ATT&CK |
|---|---|---|---|
| SIEM-101 | Mass S3 download (exfiltration) | ≥5 `GetObject` / 5 min | T1530 |
| SIEM-102 | Console login brute force | ≥4 failed logins / 5 min | T1110 |
| SIEM-103 | Reconnaissance burst | ≥8 distinct `Describe`/`List` / 5 min | T1580 |
| SIEM-104 | Credentials used from multiple IPs | ≥2 IPs / 10 min | T1078 |

## The proof (the flagship)

The engine replays a CloudTrail log that captures the **same kill chain Project 1 responds to** —
recon, key creation, admin attach, logging tampered, GuardDuty disabled, bucket made public, mass
download, brute force, root use — and detects **all 11** techniques; a benign day of CI traffic
produces **zero** (the correlation thresholds and single-event rules don't fire on normal reads).

```bash
python 12-log-detection-pipeline/attack-simulation/replay_cloudtrail.py
```

```text
>> 10:08:00 [CRITICAL] SIEM-001  root:123456789012  (T1078.004)  Root account activity
>> 10:05:40 [HIGH    ] SIEM-101  mallory            (T1530)       Mass S3 download (exfiltration)
>> 10:06:45 [HIGH    ] SIEM-102  admin              (T1110)       Console login brute force
   ... 8 more ...
  11 detection(s)   CRITICAL 1  HIGH 7  MEDIUM 3   Alert (>= HIGH): 8 alerting

Benign day: 0 detection(s) — clean
```

## Sigma: not locked to this engine

The single-event detections also ship as real **Sigma** rules
([`sigma/`](sigma/cloudtrail-detections.yml)) — the vendor-neutral detection format that converts
to Splunk SPL, Elastic EQL, etc. (`sigma convert -t splunk ...`). The engine proves the logic
offline; Sigma deploys the same logic into whatever SIEM the team already runs. Two forms, one
detection.

## How it connects to the platform

| Direction | Contract |
|---|---|
| Reads | Raw CloudTrail (`{"Records": [...]}` or an Athena/OpenSearch export) |
| Emits | `endon_core.Finding` (`Detection:CloudTrail/<id>`, tagged with the ATT&CK technique) into the bus, stores, SOC and ASFF |
| Complements | Project 1 reacts to single GuardDuty findings; this is the correlation layer under it |

## Security Decisions

1. **Correlate, don't just match.** The rules that matter slide a window over a principal's
   activity — because the dangerous behaviour is a pattern, not a record.
2. **Every detection names the adversary's move.** An ATT&CK technique on each finding turns
   "something fired" into "this is what they were doing."
3. **Detections are portable.** Shipping Sigma means the logic isn't trapped in this engine.
4. **Prove it, both ways.** A known attack must light up every detection; a benign day must stay
   dark — a passing test for coverage and for false-positive discipline.

## Limitations

- **Batch over a log, not a live stream.** It runs on a CloudTrail export; wiring it to a live
  Kinesis/Firehose stream is an operational step, not a code change to the rules.
- **Thresholds are fixed and simple.** Real deployments tune windows and counts per environment;
  here they're chosen to be explainable and testable.
- **"Multiple IPs" is a proxy for impossible travel.** True geo-velocity needs IP geolocation;
  this flags the same credentials from two IPs in a short window, which is a real, honest signal
  without claiming geolocation it doesn't have.

## Lessons Learned

- **The interesting detections are stateful.** Single-event rules are easy; the value — and the
  engineering — is in correlating across time per principal.
- **ATT&CK makes a finding actionable.** A responder or an analyst can prioritise by technique,
  not just severity.
- **Sigma keeps you honest.** Expressing a rule in a portable format forces the logic to be
  clear, and means the work isn't wasted if the SIEM changes.

## Run It

```bash
python 12-log-detection-pipeline/attack-simulation/replay_cloudtrail.py   # replay + proof
pytest 12-log-detection-pipeline/tests                                    # tests (7)
endon-siem detect 12-log-detection-pipeline/fixtures/attack.json --alert-on HIGH
```

## Project Layout

```text
12-log-detection-pipeline/
├── README.md · CASE_STUDY.md · SECURITY.md
├── architecture/{architecture.md, threat-model.md}
├── src/endon_siem/
│   ├── events.py      normalize CloudTrail records (+ parse the timestamp)
│   ├── detections.py  the catalog: single-event predicates + windowed correlations
│   ├── engine.py      run per-record and per-principal; emit endon_core Findings
│   └── report.py / cli.py
├── sigma/             portable Sigma rules (convert to Splunk/Elastic)
├── fixtures/          attack + benign CloudTrail logs
├── attack-simulation/replay_cloudtrail.py
├── evidence/
└── tests/
```
