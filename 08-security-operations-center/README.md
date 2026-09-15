# Project 8 · AWS Cloud Security Operations Center

> Part of the [Endon AI](../README.md) platform · **Status: planned**

## The Security Problem

Security signals are spread across GuardDuty, Security Hub, Config, scanner reports and
incident records. Without one view, nobody can answer the basic questions: *How exposed
are we right now? What happened overnight? What did the automation already handle?*

## What it will do

A Python FastAPI application over the platform's incident and finding tables:

```text
                AWS SECURITY OPERATIONS CENTER

Security Score              82/100

Critical Findings            2
High Findings                7
Medium Findings             14

GuardDuty                    ACTIVE
Security Hub                 ACTIVE
CloudTrail                   ACTIVE
AWS Config                   ACTIVE

Recent incidents
09:42  IAM privilege escalation path      iam-risk-review     MONITORING
09:31  EC2 cryptomining activity          compromised-ec2     CONTAINED
08:17  Public S3 bucket                   s3-public-exposure  CONTAINED
```

- REST API: `/api/summary`, `/api/incidents`, `/api/incidents/{id}` (full timeline), `/api/findings`
- Security score from open findings weighted by severity, and detective-service health checks
- Server-rendered pages with Jinja2; access restricted with Amazon Cognito

## How it connects to the platform

| Direction | Contract |
|---|---|
| Reads | Incidents and findings tables (`endon_core.store`) |
| Consumes | `Endon Incident Updated` and `Endon Forensics Completed` for live updates |
| Shows | Output of every other component: incidents (1), IAM risk (2), posture (3), evidence (4), data protection (5) |
