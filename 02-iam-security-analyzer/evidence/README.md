# Evidence

| Evidence | Source | Status |
|---|---|---|
| [`offline-scan.txt`](offline-scan.txt) | Offline scan of the vulnerable account | Captured |
| [`iam-assessment.html`](iam-assessment.html) | HTML report from the same scan | Captured |
| `console-scan.png` | Terminal output of `offline_scan.py` | To capture |
| `html-report.png` | The HTML report open in a browser | To capture |
| `escalation-path.png` | The `mallory -> role -> admin` path highlighted | To capture |
| `live-scan.png` | `endon-iam-analyzer scan` against a real account | To capture |
| `s3-report.png` | An HTML assessment stored in the evidence bucket by the scheduled Lambda | To capture |

## Capturing live evidence

1. Run the offline scan and screenshot the console output and the HTML report.
2. In a lab account: `endon-iam-analyzer scan --region us-east-1 --formats console,html
   --output-dir reports/`. Screenshot the run.
3. `cdk deploy EndonIamAnalyzer`, invoke it once, and capture the HTML report written to
   `iam-assessments/` in the evidence bucket.
4. Redact account IDs before publishing.
