# Evidence

| Evidence | Source | Status |
|---|---|---|
| [`offline-scan.txt`](offline-scan.txt) | Offline scan + detection benchmark (26/26) | Captured |
| [`posture-assessment.html`](posture-assessment.html) | HTML report from the same scan | Captured |
| `console-scan.png` | Terminal output of `offline_scan.py`, incl. the benchmark block | To capture |
| `html-report.png` | The HTML report open in a browser | To capture |
| `auto-remediation.png` | A public bucket closed by Project 1 after the scan published the finding | To capture |
| `live-scan.png` | `endon-posture-scanner scan` against a real account | To capture |
| `s3-report.png` | An HTML assessment stored in the evidence bucket by the scheduled Lambda | To capture |

## Capturing live evidence

1. Run `offline_scan.py` and screenshot the console output (especially the DETECTION
   BENCHMARK block) and the HTML report.
2. In a lab account: `endon-posture-scanner scan --region us-east-1 --formats console,html
   --output-dir reports/`. Screenshot the run.
3. Create a public bucket, deploy the platform, and let the scheduled scan publish the
   finding; capture Project 1 re-enabling Block Public Access.
4. Capture the HTML report written to `posture-assessments/` in the evidence bucket.
5. Redact account IDs before publishing.
