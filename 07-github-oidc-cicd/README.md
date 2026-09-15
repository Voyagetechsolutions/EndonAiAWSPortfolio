# Project 7 · Passwordless GitHub → AWS Secure CI/CD Pipeline

> Part of the [Endon AI](../README.md) platform · **Status: planned**

## The Security Problem

The common way to deploy from GitHub Actions is to store `AWS_ACCESS_KEY_ID` and
`AWS_SECRET_ACCESS_KEY` as repository secrets. Those are long-lived credentials: they
never expire, they get copied, and anyone who can run a workflow can use them.

## What it will do

```text
GitHub Actions  →  OIDC token  →  AWS STS AssumeRoleWithWebIdentity  →  temporary credentials  →  scoped deploy role
```

- IAM OIDC identity provider for `token.actions.githubusercontent.com`, created with CDK for Python.
- Deploy role trust restricted by `aud` = `sts.amazonaws.com` and `sub` =
  `repo:<owner>/<repo>:ref:refs/heads/main`. Forks, other branches and other repositories cannot assume it.
- The deploy role may only assume the CDK bootstrap deployment roles, under a permissions boundary.
- Pipeline stages: `ruff` → `pytest` → `cdk synth` → **IAM analyzer gate (Project 2)** →
  deploy → **posture scan (Project 3)**. All logic lives in Python scripts. The
  workflow file is YAML only because GitHub Actions requires it.

**Attack demonstration.** A compromised workflow tries `s3:DeleteBucket`,
`iam:CreateUser` and `iam:AttachUserPolicy`, and every call is denied and recorded in CloudTrail.

Case study: *Eliminating Long-Lived AWS Credentials from CI/CD Using GitHub OIDC.*

## How it connects to the platform

| Direction | Contract |
|---|---|
| Deploys | Every Endon stack; the only path allowed to change the responder (enforced by Project 6 SCPs) |
| Uses | IAM analyzer (Project 2) and posture scanner (Project 3) as quality gates |
