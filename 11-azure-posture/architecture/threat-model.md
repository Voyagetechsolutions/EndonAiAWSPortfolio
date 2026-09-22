# Threat Model: Azure Posture Scanner

## Scope

CSPM checks over an Azure subscription's resources, and the CI gate they drive. The goal is to
close the Azure half of a multi-cloud estate's blind spot — the same class of misconfiguration
Project 3 catches in AWS, caught in Azure and surfaced in the same SOC.

## Assets

| Asset | Why it matters |
|---|---|
| Blob data in Storage accounts | Public blob access is a data exposure |
| Network exposure (NSGs) | An Internet-sourced admin rule is a way in |
| Data at rest (managed disks) | Unencrypted disks fail data-protection controls |
| Key Vault | No purge protection / public access risks the keys that protect everything else |
| Detective coverage (Defender) | Defender off means Azure-native detection is blind |

## Attackers / failure sources

| Source | Position | Concern |
|---|---|---|
| Careless engineer | Can change a resource | Public Storage "to share a report", an NSG left open after a migration |
| Attacker scanning the internet | External | Finds the public blob endpoint or the open NSG port |
| Drift over time | The subscription | Defender plan lapses to Free; a disk created without encryption |

## Threats and controls

| # | Threat | Control | Proven by |
|---|---|---|---|
| 1 | Public blob data exposure | AZ-STG-001 | benchmark |
| 2 | Unencrypted transport to Storage | AZ-STG-002 | benchmark |
| 3 | Storage reachable from all networks | AZ-STG-003 | benchmark |
| 4 | SSH/RDP open to the Internet | AZ-NSG-001 | `test_nsg_admin_vs_other_port` |
| 5 | Any Internet ingress | AZ-NSG-002 | benchmark |
| 6 | Unencrypted managed disk | AZ-DISK-001 | `test_disk_keyvault_defender` |
| 7 | Key Vault without purge protection | AZ-KV-001 | benchmark |
| 8 | Key Vault reachable publicly | AZ-KV-002 | benchmark |
| 9 | Defender for Cloud not enabled (blind spot) | AZ-DEF-001 | benchmark |
| 10 | Scanner passes an insecure subscription (false negative) | benchmark asserts all 9 fire | `test_every_control_fires...` |
| 11 | Scanner blocks a safe subscription (false positive) | secure fixture must produce nothing | `test_the_secure_subscription...` |

## Residual risks

| Risk | Why it remains | Treatment |
|---|---|---|
| Snapshot, not continuous | It scans an inventory at query time | AZ-DEF-001 checks Defender (continuous) is on; run on a schedule |
| Per-resource, not cross-resource | Checks read one resource's properties | Private endpoints / policy assignments are a future control set |
| 9 controls is not exhaustive | Curated high-value set | Extend the catalog over time |
| Live collection needs credentials | The collector reads the subscription | Reader + Security Reader only; scoped, rotated service principal |
