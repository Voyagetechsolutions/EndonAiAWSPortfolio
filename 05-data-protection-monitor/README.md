# Project 5 · AWS Data Protection & Secrets Exposure Monitor

> Part of the [Endon AI](../README.md) platform · **Status: planned**

## The Security Problem

Data exposure is usually accidental. A developer puts a database password in a Lambda
environment variable, uploads customer records to the wrong bucket, leaves a volume
unencrypted, commits an access key, or writes a KMS key policy that trusts everyone.

## What it will do

| Detection | Source |
|---|---|
| Sensitive data (PII, credentials) in S3 | Amazon Macie findings |
| Secrets in Lambda environment variables and EC2 user data | Python pattern and entropy checks |
| Exposed AWS access keys | AWS Health `AWS_RISK_CREDENTIALS_EXPOSED` events |
| Unencrypted S3, EBS and RDS storage | boto3 checks |
| KMS key policies with broad principals; Secrets Manager rotation disabled | boto3 checks |

Demo: fake PII is placed in a test bucket, Macie detects it, and the monitor classifies
the severity, restricts the bucket, tags it, opens an incident and alerts.

## How it connects to the platform

| Direction | Contract |
|---|---|
| Consumes | Macie findings and AWS Health events from EventBridge |
| Publishes | `Endon Finding`, source `endon.data-protection`, types such as `DataProtection:S3/SensitiveDataPubliclyAccessible`, `DataProtection:Lambda/SecretInEnvironment` |
| Response engine | Public sensitive data triggers the `s3-public-exposure` playbook automatically |
| SOC (Project 8) | Data protection findings and encryption coverage |
