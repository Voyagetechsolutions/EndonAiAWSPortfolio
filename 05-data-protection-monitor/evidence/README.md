# Evidence

| Evidence | Source | Status |
|---|---|---|
| [`offline-scan.txt`](offline-scan.txt) | Offline scan of a leaky account + redaction check | Captured |
| `console-scan.png` | Terminal output of `offline_scan.py` | To capture |
| `html-report.png` | The redacted HTML report in a browser | To capture |
| `macie-remediation.png` | A public sensitive-data bucket closed by Project 1 | To capture |
| `live-scan.png` | `endon-data-protection scan` against a real account | To capture |
| `no-getsecretvalue.png` | The scanner's IAM policy showing ListSecrets but no GetSecretValue | To capture |

## Capturing live evidence

1. Run `offline_scan.py`; screenshot the console output and the redaction check line.
2. In a lab account, deploy the platform, put a secret in a Lambda env var, and run the
   scheduled scan (or the CLI). Capture the redacted finding.
3. Enable Macie, place fake PII in a public test bucket, and let Macie classify it; capture
   Project 1 re-enabling Block Public Access.
4. Screenshot the scanner role's IAM policy to show `secretsmanager:ListSecrets` without
   `GetSecretValue`.
5. Redact account IDs before publishing. (Secret values are already redacted by the tool.)
