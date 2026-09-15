# Project 4 · Automated EC2 Incident Response & Forensics

> Part of the [Endon AI](../README.md) platform · **Status: planned**

## The Security Problem

When an EC2 instance is compromised, the instinct is to terminate it. That destroys
exactly what an investigation needs: memory, running processes, disk contents and
network state. Containment has to preserve evidence and produce a chain of custody.

## What it will do

Triggered for every instance the response engine isolates:

```text
Forensics requested
  → verify isolation (quarantine SG, termination protection)
  → capture instance metadata, tags, ENIs, IAM instance profile, console output
  → snapshot every EBS volume (encrypted, tagged with the incident ID)
  → collect CloudTrail events for the instance and its role
  → optional volatile data collection through SSM Run Command
  → write evidence + SHA-256 manifest to the Object Lock evidence bucket
  → publish Forensics Completed; append to the incident timeline
```

It will produce a timestamped incident timeline, for example:

```text
09:31:04 Suspicious activity detected
09:31:05 Incident created
09:31:06 EC2 quarantined
09:31:09 EBS snapshot started
09:31:14 Evidence stored (manifest sha256: …)
```

## How it connects to the platform

| Direction | Contract |
|---|---|
| Consumes | `Endon Forensics Requested` from the response engine (Project 1) |
| Publishes | `Endon Forensics Completed`, source `endon.forensics` |
| Stores | Evidence in the platform's Object Lock evidence bucket, encrypted with the platform KMS key |
| SOC (Project 8) | Shows evidence status and manifest per incident |
