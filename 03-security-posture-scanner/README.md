# Project 3 · AWS Cloud Security Posture Scanner

> Part of the [Endon AI](../README.md) platform · **Status: planned**

## The Security Problem

Most cloud breaches don't start with an exploit. They start with a misconfiguration: a
public bucket, SSH open to the internet, logging turned off, an unencrypted database.
Knowing that AWS Config exists is not the same as understanding how these
misconfigurations are found.

## What it will do

A modular Python scanner, one module per service, with stable control IDs and
remediation guidance for every check:

```text
03-security-posture-scanner/src/endon_posture/
├── checks/  iam  s3  ec2  rds  cloudtrail  kms  secrets  networking
├── findings.py     control catalog → endon_core.Finding
└── reports/        json  csv  html
```

| Example control | Severity | Check |
|---|---|---|
| `S3-001` | CRITICAL | Bucket publicly accessible (ACL, policy, Block Public Access) |
| `EC2-004` | HIGH | Security group allows SSH/RDP from `0.0.0.0/0` |
| `IAM-003` | HIGH | Administrative wildcard privileges |
| `CT-001` | HIGH | CloudTrail disabled or not multi-region |
| `KMS-002` | MEDIUM | Customer-managed key rotation disabled |

It will be benchmarked against a deliberately vulnerable environment with a known number
of planted misconfigurations, and will report its detection rate.

## How it connects to the platform

| Direction | Contract |
|---|---|
| Publishes | `Endon Finding`, source `endon.posture-scanner`, types such as `Posture:S3/BucketPubliclyAccessible`, `Posture:EC2/AdminPortOpenToInternet` |
| Response engine | `Posture:S3/BucketPubliclyAccessible` is remediated automatically (Block Public Access); other controls alert |
| Detection & Response (Project 1) | Catches attacker changes that are not GuardDuty findings, such as the SSH rule opened in the Project 1 replay |
| CI/CD (Project 7) | Post-deployment scan of the environment |
| SOC (Project 8) | Supplies the posture score and control results |
