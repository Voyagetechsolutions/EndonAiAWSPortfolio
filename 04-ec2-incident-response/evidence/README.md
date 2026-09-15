# Evidence

| Evidence | Source | Status |
|---|---|---|
| [`offline-forensics.txt`](offline-forensics.txt) | Offline collection against an emulated isolated instance | Captured |
| `collection-timeline.png` | Terminal output of `offline_forensics.py` | To capture |
| `manifest.png` | The chain-of-custody `manifest.json` (evidence list + hashes) | To capture |
| `object-lock.png` | S3 console: an evidence object with GOVERNANCE retention | To capture |
| `snapshots.png` | EC2 console: evidence snapshots tagged `endon:evidence=true` | To capture |
| `live-collection.png` | A real lab account: a case triggered by Project 1 isolating an instance | To capture |

## Capturing live evidence

1. Run `offline_forensics.py`; screenshot the timeline and chain-of-custody output.
2. In a lab account, deploy the platform, trigger a GuardDuty EC2 finding (Project 1's
   `simulate_credential_compromise` or a sample finding), and let Project 1 isolate the
   instance. The forensics engine runs automatically.
3. Capture: the `manifest.json` in the evidence bucket, the object's Object Lock retention,
   the tagged snapshots, and the `Endon Forensics Completed` event.
4. Redact account IDs and any secrets visible in console output before publishing.
