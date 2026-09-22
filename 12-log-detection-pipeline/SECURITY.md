# Security Notes: Log Detection Pipeline

See the repository-wide [SECURITY.md](../SECURITY.md) for vulnerability reporting.

## Operating notes

- **Read-only over logs.** The engine consumes CloudTrail JSON and emits findings; it never calls
  AWS and needs no credentials. Give it a log export, an Athena result, or a stream batch.
- **Feed it the whole trail, not a sample.** Correlation rules need every event for a principal in
  the window to fire correctly; a sampled or filtered log will miss bursts.
- **Alert on HIGH+, tune the rest.** `--alert-on HIGH` surfaces the exfiltration/brute-force/
  tampering detections; MEDIUM (key created, SG opened, recon) is context. Thresholds and windows
  are deliberately simple — tune them per environment before production.
- **Detections are portable, so keep them in sync.** The Sigma rules mirror the single-event
  engine rules; if you change one, change the other, or convert from Sigma as the source of truth.

## Trust and scope

- **CloudTrail is the trust anchor.** These detections assume the trail is intact — which is why
  SIEM-002 (logging tampered) and SIEM-003 (detective services disabled) exist: they catch the
  attacker trying to blind the very log this engine reads. Protect the trail itself with an
  organization trail to a locked Log Archive account (Project 6).
- **Batch, not streaming, here.** Wiring the engine to a live Kinesis/Firehose stream is an
  operational integration; the detection logic is unchanged.
- **"Multiple IPs" is not geolocation.** SIEM-104 flags the same credentials from two IPs in a
  short window — a real signal — without claiming impossible-travel geolocation it does not compute.

## Using it

```bash
# Over a CloudTrail export:
endon-siem detect trail.json --alert-on HIGH

# Deploy the same single-event rules into a SIEM via Sigma:
pip install sigma-cli
sigma convert -t splunk sigma/cloudtrail-detections.yml
```
