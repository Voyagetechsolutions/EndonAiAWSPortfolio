# Threat Model: Data Protection Monitor

## Scope

The secret-detection engine, the config scanners, the Macie/Health event consumer, and the
two IAM roles. The monitor detects exposure and publishes findings; it changes nothing.

## Assets

| Asset | Why it matters |
|---|---|
| The secrets it detects | The plaintext must never be stored, logged or emitted |
| The findings and reports | A map of where the account's secrets are — sensitive by nature |
| The monitor's roles | Broad read across Lambda, EC2, Secrets Manager |

## Threats (STRIDE)

| # | Category | Threat | Mitigation | Verified by |
|---|---|---|---|---|
| I1 | Information disclosure | The monitor emits a plaintext secret in a finding/report/log | Redaction at the engine boundary; every value is `xxx...yyy (sha256:…)` | `test_no_raw_secret_ever_appears_in_a_finding`, `test_reports_are_redacted_end_to_end` |
| I2 | Information disclosure | The monitor *reads* a secret's value, becoming an exfiltration path | The role has `ListSecrets` but not `GetSecretValue`/`BatchGetSecretValue` | `test_never_reads_secret_values` |
| E1 | Elevation | The monitor is abused to change resources | Read-only across every inspected service | `test_inspection_permissions_are_read_only` |
| T1 | Tampering | A finding drives an unsafe automatic action | Only public sensitive data is auto-remediated (by Project 1, guardrailed); secrets are triage | `test_secret_findings_route_to_review_not_containment` |
| S1 | Spoofing | A forged Endon finding triggers containment | Endon-sourced findings reach only remediation/triage playbooks (Project 1 trust boundary) | Project 1 tests |
| D1 | Denial | Noise (false positives) makes the tool ignored | Placeholder suppression + secret-named-variable gate on the entropy path | `test_placeholders_and_references_are_not_flagged`, `test_plain_config_value_without_secret_name_is_not_flagged` |
| D2 | Denial | One failing scanner aborts the run | Per-scanner exceptions are caught and recorded | scanner `errors` handling |

## False positives and false negatives

| Decision | Direction | Rationale |
|---|---|---|
| Entropy path requires a secret-named variable | avoid false positives | High entropy alone flags hashes and build IDs |
| Placeholders and `${...}`/`<...>` references suppressed | avoid false positives | These are not secrets |
| Signatures are conservative and versioned | accepts false negatives | Better to miss a novel format than flood on entropy |
| Redaction is lossy (fingerprint only) | accepts reduced detail | The plaintext must never be recoverable from a finding |

## Residual risks

| Risk | Why it remains | Treatment |
|---|---|---|
| Secrets in object *contents* (files in S3) | This component reads config, not object bodies | Amazon Macie (consumed here) covers S3 object classification |
| Novel secret formats | Signatures lag | Entropy safety net; add signatures as formats appear |
| Exposed key not auto-disabled | Endon findings don't trigger principal containment | Reported CRITICAL; auto-disable belongs to Project 1 gated behind AWS-source trust |
| A report leaks if mishandled downstream | The report still describes *where* secrets are | Stored only in the KMS-encrypted, Object Lock evidence bucket; restrict the prefix |
