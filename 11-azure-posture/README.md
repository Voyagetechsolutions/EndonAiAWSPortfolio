# Project 11 · Azure Posture Scanner

> Part of the [Endon AI](../README.md) platform · **Status: built and tested** · Azure + Python

The platform's second cloud. This scans an **Azure** subscription for the misconfigurations
that matter — public storage accounts, NSGs open to the Internet, unencrypted disks, Key Vaults
without purge protection, Microsoft Defender for Cloud left off — and emits the **same
`endon_core.Finding`** as the AWS scanners, so an Azure risk and an AWS risk land in one SOC,
one report, one ASFF feed. Most real estates are multi-cloud; so is this.

---

## The Security Problem

Security teams rarely get to be single-cloud. A company runs its main workloads on AWS and its
data platform on Azure, and the Azure side has the same failure modes with different names: an
S3 bucket public via ACL becomes a Storage account with `allowBlobPublicAccess`; a `0.0.0.0/0`
security group becomes an NSG rule sourced from `Internet`; an unencrypted EBS volume becomes a
managed disk with no encryption. A posture tool that only speaks AWS is blind to half the
estate.

**Goal:** cover Azure's core CSPM controls with the same severity model and finding format as
Project 3, so "how exposed are we right now?" spans both clouds — and prove it, like everything
else.

## What it checks

[`controls.py`](src/endon_azure/controls.py) is the Azure catalog (9 controls); detection is in
[`checks.py`](src/endon_azure/checks.py).

| Control | Flags | Severity |
|---|---|---|
| AZ-STG-001 | Storage account allows public blob access | CRITICAL |
| AZ-STG-002 / 003 | Allows HTTP / reachable from all networks | HIGH / MEDIUM |
| AZ-NSG-001 / 002 | SSH/RDP from the Internet / any Internet ingress | HIGH / MEDIUM |
| AZ-DISK-001 | Managed disk not encrypted | HIGH |
| AZ-KV-001 / 002 | Key Vault no purge protection / public network access | HIGH / MEDIUM |
| AZ-DEF-001 | Microsoft Defender for Cloud plan not enabled | MEDIUM |

Each maps to the same SCS-C03 domain its AWS twin does — Storage/disk to Data Protection, NSG
to Infrastructure Security, Defender to Detection — so the coverage map stays coherent across
clouds.

## How it reads Azure (offline-testable, live-capable)

The scanner runs entirely on **Azure Resource Graph** JSON — the `id`, `type`, `location` and
`properties` of each resource, exactly what `az graph query` or the SDK returns. That single
decision buys two things:

- **Live:** [`collector.py`](src/endon_azure/collector.py) runs one Resource Graph (KQL) query
  through the Azure SDK (`azure-identity` + `azure-mgmt-resourcegraph`) to inventory a whole
  subscription — the way a real CSPM tool does, one query, not an API call per service.
- **Offline:** the checks operate on that JSON, so the tests run against committed fixtures with
  **no Azure account and no SDK installed** (the SDK is an optional `[live]` extra). Same
  hermetic discipline as the moto-backed AWS projects.

## The proof (the flagship)

Coverage is measured, not claimed. An insecure subscription fixture trips **all 9** controls; a
hardened one trips none. The [benchmark test](tests/test_scanner.py) asserts exactly that.

```bash
python 11-azure-posture/attack-simulation/scan_insecure_subscription.py
```

```text
>> [CRITICAL] AZ-STG-001  acmepublic   Storage account allows public blob access
>> [HIGH    ] AZ-NSG-001  acme-nsg     NSG allows SSH/RDP inbound from the Internet
>> [HIGH    ] AZ-DISK-001 acme-data    Managed disk is not encrypted
   ... 6 more ...
  9 finding(s)   CRITICAL 1  HIGH 4  MEDIUM 4
  Gate (fail-on HIGH): FAILED — 5 blocking

Hardened subscription: 0 finding(s) — gate PASSED
```

## How it connects to the platform

| Direction | Contract |
|---|---|
| Emits | `endon_core.Finding` (`AzurePosture:<Service>/<Name>`, tagged `cloud=azure`) into the same bus, stores, SOC and ASFF |
| Mirrors | Project 3 — this is the AWS posture scanner's Azure sibling, sharing its control-catalog shape |
| Gates | `endon-azure scan --fail-on HIGH` slots into the Project 7 pipeline like the other scanners |

## Security Decisions

1. **One finding format, many clouds.** An Azure finding is indistinguishable from an AWS one to
   the SOC — which is the whole point of a platform.
2. **Resource Graph, not per-service polling.** One query inventories the subscription; the
   scanner stays fast and the collector stays simple.
3. **Live optional, offline default.** The Azure SDK is an extra, so the checks and tests need
   nothing but the standard library and `endon-core`.
4. **Prove it.** An insecure/secure benchmark makes Azure coverage a passing test.

## Limitations

- **9 controls is a curated set,** the highest-value Azure CSPM checks, not exhaustive coverage
  of every Azure service.
- **Point-in-time.** It scans an inventory snapshot; continuous evaluation is Microsoft Defender
  for Cloud's job (which control AZ-DEF-001 checks is switched on).
- **Reads resource properties.** Cross-resource posture (a private endpoint in a separate
  resource, a policy assignment) is not fully modelled — the same boundary as the Terraform
  scanner.

## Lessons Learned

- **Multi-cloud is mostly translation.** The dangerous states are the same across clouds; the
  work is mapping each cloud's property names to the same control idea and the same finding.
- **Resource Graph is the right layer.** Inventorying via one KQL query is dramatically simpler —
  and more like production CSPM — than walking each service's management API.
- **The shared contract earned its keep again.** Adding a second cloud took a catalog and a set
  of predicates; the bus, stores, SOC and ASFF were already there.

## Run It

```bash
python 11-azure-posture/attack-simulation/scan_insecure_subscription.py   # scan + proof
pytest 11-azure-posture/tests                                             # tests (8)
endon-azure scan 11-azure-posture/fixtures/insecure.json --fail-on HIGH
pip install -e '11-azure-posture[live]' && endon-azure scan --live --subscription <id>
```

## Project Layout

```text
11-azure-posture/
├── README.md · CASE_STUDY.md · SECURITY.md
├── architecture/{architecture.md, threat-model.md}
├── src/endon_azure/
│   ├── resources.py   normalize Azure Resource Graph rows
│   ├── controls.py    the Azure CSPM catalog (9)
│   ├── checks.py      one predicate per control
│   ├── scanner.py     checks -> endon_core Findings
│   ├── collector.py   live inventory via the Azure SDK (optional [live] extra)
│   └── report.py / cli.py
├── fixtures/          insecure/secure Resource Graph JSON
├── attack-simulation/scan_insecure_subscription.py
├── evidence/
└── tests/
```
