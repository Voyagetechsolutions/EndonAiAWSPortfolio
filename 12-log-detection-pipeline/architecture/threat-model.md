# Threat Model: Log Detection Pipeline

## Scope

A detection engine over CloudTrail — single-event signatures and per-principal windowed
correlations — and the alerting gate it drives. The goal is to detect the multi-step attacks that
individual-finding tools miss, and to catch the attacker's attempt to blind the log itself.

## Assets

| Asset | Why it matters |
|---|---|
| The account's data (S3) | Mass download is exfiltration |
| Identity (IAM) | Key creation and admin attach are persistence/escalation |
| The audit log (CloudTrail) | The trail is the trust anchor; blinding it precedes the rest |
| Detective coverage (GuardDuty/Config) | Disabling it removes the other eyes |
| Console access | Brute force and stolen-credential use are the way in |

## Attackers

| Attacker | Position | Behaviour the engine catches |
|---|---|---|
| Stolen-credential attacker | Holds a valid access key | Recon burst, key creation, admin attach, mass download, second-IP use |
| Insider | Legitimate access | Root usage, quietly making a bucket public, disabling detection |
| Credential-stuffer | External, hitting the console | Brute-force login attempts |

## Threats and detections

| # | Threat (ATT&CK) | Detection | Proven by |
|---|---|---|---|
| 1 | Root account used (T1078.004) | SIEM-001 | benchmark |
| 2 | Logging tampered (T1562.008) | SIEM-002 | benchmark |
| 3 | Detective services disabled (T1562.001) | SIEM-003 | benchmark |
| 4 | Persistence key created (T1098.001) | SIEM-004 | benchmark |
| 5 | Privilege escalation to admin (T1098) | SIEM-005 | benchmark |
| 6 | Bucket made public (T1530) | SIEM-006 | benchmark |
| 7 | SG opened to the internet (T1562.007) | SIEM-007 | benchmark |
| 8 | Data exfiltration — mass download (T1530) | SIEM-101 | `test_mass_download...` |
| 9 | Brute force (T1110) | SIEM-102 | benchmark |
| 10 | Reconnaissance (T1580) | SIEM-103 | benchmark |
| 11 | Stolen credentials — multi-IP (T1078) | SIEM-104 | `test_multi_ip...` |
| 12 | The engine misses the attack (false negative) | benchmark asserts all 11 fire | `test_every_detection_fires...` |
| 13 | The engine alerts on a benign day (false positive) | benign fixture must be silent | `test_benign_traffic_is_quiet` |

## The self-blinding problem (and the answer)

| Concern | Mitigation |
|---|---|
| The attacker stops CloudTrail before acting | SIEM-002/003 detect the tampering itself; protect the trail with an org trail to a locked Log Archive account (Project 6) |
| A filtered/sampled log hides the burst | Feed the whole trail; correlation needs every event in the window |
| Detection is batch, so slow | Wire to a live stream for near-real-time; the rules are unchanged |

## Residual risks

| Risk | Why it remains | Treatment |
|---|---|---|
| Fixed thresholds may over/under-fire | Chosen for clarity and testability | Tune windows/counts per environment; the benign test guards the floor |
| "Multiple IPs" ≠ geolocation | No geoip in the offline engine | Honest, narrower signal; add geo-velocity where an IP database is available |
| Batch, not streaming, here | Offline-first design | Streaming is an operational integration, not a rule change |
