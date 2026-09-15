# Project 2 · IAM Least-Privilege & Privilege-Escalation Analyzer

> Part of the [Endon AI](../README.md) platform · **Status: planned**

## The Security Problem

IAM drifts toward over-permission. Accounts accumulate `AdministratorAccess`
attachments, `"Action": "*"` policies, users nobody remembers, access keys years old,
and roles trusted by accounts outside the organization. The most dangerous risks are
the non-obvious ones: a role that looks harmless but holds `iam:PassRole` plus
`lambda:CreateFunction` can make itself an administrator.

## What it will do

A Python and boto3 analyzer that pulls a complete IAM snapshot
(`GetAccountAuthorizationDetails`) and reports:

| Severity | Check |
|---|---|
| CRITICAL | Principals with administrator-equivalent access |
| CRITICAL | Privilege-escalation paths, e.g. `iam:PassRole` + `lambda:CreateFunction`, `iam:CreatePolicyVersion`, `iam:AttachUserPolicy`, `iam:UpdateAssumeRolePolicy` |
| CRITICAL | Role trust policies that allow external accounts without an `sts:ExternalId` condition |
| HIGH | Policies with wildcard actions or resources |
| HIGH | Console users without MFA; access keys older than 90 days |
| MEDIUM | Permissions unused for 90 days (IAM Access Advisor) |

It will also generate least-privilege replacement policies from access activity, and
produce console, JSON, CSV and HTML reports.

## How it connects to the platform

| Direction | Contract |
|---|---|
| Publishes | `Endon Finding` on `endon-security-bus`, source `endon.iam-analyzer`, types such as `IAM:Role/PrivilegeEscalationPath`, `IAM:User/AdministratorAccess`, `IAM:AccessKey/Stale` |
| Response engine | Routes `IAM:*` to the `iam-risk-review` playbook: alert, never automatic permission removal |
| CI/CD (Project 7) | Runs as a pipeline gate against synthesized CDK templates and fails the build on CRITICAL findings |
| SOC (Project 8) | Supplies the IAM risk score |
