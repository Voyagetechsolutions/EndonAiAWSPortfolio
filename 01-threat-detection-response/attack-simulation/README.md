# Attack Simulation

Three ways to attack the response engine, from zero risk to a live lab.

| Script | Where it runs | What it proves |
| --- | --- | --- |
| `offline_replay.py` | Your laptop, emulated AWS (moto) | The full kill chain is detected, contained and verified through the AWS APIs, with no account needed |
| `generate_sample_findings.py` | Real account, GuardDuty sample findings | The deployed pipeline (GuardDuty → EventBridge → Lambda → DynamoDB → SNS) is wired correctly. Samples are always handled in dry-run |
| `simulate_credential_compromise.py` | Dedicated lab account | Real GuardDuty detections from real attacker behaviour trigger real containment |

## The scenario

An access key belonging to a CI user leaks. Before any alert fires, the attacker:

1. Enumerates S3 buckets from an unfamiliar IP (*T1580 Cloud Infrastructure Discovery*)
2. Creates a second access key for persistence (*T1098.001 Additional Cloud Credentials*)
3. Opens SSH to the internet on the web tier
4. Stops CloudTrail to hide what comes next (*T1562.008 Disable or Modify Cloud Logs*)
5. Removes S3 Block Public Access from a customer data bucket (*T1530 Data from Cloud Storage*)
6. Runs a cryptominer on a web server (*T1496 Resource Hijacking*)

## 1. Offline replay

```bash
python 01-threat-detection-response/attack-simulation/offline_replay.py
```

It prints the attack, each incident's timeline, then checks the final account state
through the AWS APIs: keys inactive, quarantine policy attached, logging restored,
bucket closed, instance isolated but still running. Output is captured in
[`../evidence/offline-replay.txt`](../evidence/offline-replay.txt).

## 2. GuardDuty sample findings (after `cdk deploy`)

```bash
python 01-threat-detection-response/attack-simulation/generate_sample_findings.py --region us-east-1
```

## 3. Live credential compromise (lab account only)

```bash
python 01-threat-detection-response/attack-simulation/simulate_credential_compromise.py setup --lab-account <id> --trail endon-lab-trail --attacker-ip <your-public-ip> --threat-list-bucket <bucket>
```

```bash
python 01-threat-detection-response/attack-simulation/simulate_credential_compromise.py attack --lab-account <id> --trail endon-lab-trail
```

```bash
python 01-threat-detection-response/attack-simulation/simulate_credential_compromise.py cleanup --lab-account <id>
```

Deploy with `-c endon:responseMode=enforce` to see containment. In `dry_run` the
incidents record what would have happened.
