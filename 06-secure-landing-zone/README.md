# Project 6 · Secure Multi-Account AWS Landing Zone

> Part of the [Endon AI](../README.md) platform · **Status: planned**

## The Security Problem

In a single AWS account, anyone with enough permissions can switch off the controls
that watch them. Security has to sit above the workload accounts, in guardrails that
no account administrator can remove.

## What it will do

AWS CDK for Python, deploying:

```text
Organization
├── Management
├── Security OU
│   ├── Security Tooling   delegated admin: GuardDuty, Security Hub, Config, Macie · Endon platform
│   └── Log Archive        organization CloudTrail, Config history (Object Lock)
├── Workloads OU
│   ├── Production
│   └── Development
└── Sandbox OU
```

| Service control policy | Purpose |
|---|---|
| Protect logging | Deny `cloudtrail:StopLogging`, `DeleteTrail`, `UpdateTrail` outside the security role |
| Protect detection | Deny disabling GuardDuty, Security Hub, Config |
| Region allowlist | Deny actions outside approved regions (global services exempt) |
| Prevent public S3 | Deny removing account- and bucket-level Block Public Access |
| Protect Endon AI | Deny modifying `endon-*` roles, rules and functions outside the deployment pipeline |
| Stay in the organization | Deny `organizations:LeaveOrganization` |

## How it connects to the platform

| Direction | Contract |
|---|---|
| Provides | Organization-wide GuardDuty, Security Hub and Config findings for the response engine |
| Hosts | The Endon platform and response engine in the Security Tooling account |
| Protects | The responder and its detection pipeline from account administrators (residual risk in Project 1's threat model) |
