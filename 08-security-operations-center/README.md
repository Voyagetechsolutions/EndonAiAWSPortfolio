# Project 8 · AWS Cloud Security Operations Center

> Part of the [Endon AI](../README.md) platform · **Status: built and tested** · FastAPI + Cognito (CDK)

The single pane of glass over the whole platform. A read-only FastAPI console that reads the
same incident and finding stores every other component writes, turns them into one
**explainable security score**, checks that the detectors are actually switched on, and shows
every incident from detection to containment. It is the answer to "how exposed are we right
now, and what did the automation already handle?"

---

## The Security Problem

By the time you have eight security tools, you have a new problem: the signal is scattered.
GuardDuty is in one console, Security Hub in another, the IAM analysis in a report, the
incidents in a table. Nobody can answer the basic questions — *How exposed are we? What
happened overnight? What did automation already contain?* — without stitching four tabs
together. And a dashboard that summarizes all this is itself a target: if it can *act*, then
whoever reaches it can act through it; if it serves without authentication, it leaks the
map of your weaknesses to anyone who finds the URL.

**Goal:** one view that aggregates the whole platform, quantifies exposure in a number a human
can trust, is impossible to turn into a weapon (read-only by construction), and serves nothing
without authentication.

## What it does

A FastAPI application over the platform's `endon_core` stores, with two views of the same data:

- **REST API** — `GET /api/summary`, `/api/incidents`, `/api/incidents/{id}` (full action list
  and timeline), `/api/findings`. Every route is a `GET`; there is no route that mutates state.
- **Server-rendered console** — a dark security-ops board (Jinja2, autoescaped) showing the
  security score, findings by severity, detective-control health, and recent incidents, each
  linking to its own page.

```text
ENDON AI - SECURITY OPERATIONS CENTER

Security Score               28/100   (grade F)

Critical findings           1
High findings               2
Medium findings             2
Low findings                1

GuardDuty                 ACTIVE
Security Hub              INACTIVE       <- a blind spot the score accounts for
CloudTrail                ACTIVE
AWS Config                ACTIVE

Recent incidents
  09:42  Role can escalate to admin ...     iam-risk-review       MONITORING
  09:31  Access key used from a mali...     compromised-iam-user  CONTAINED
  08:17  S3 bucket is publicly readable     s3-public-exposure    CONTAINED
```

## The security score (the flagship)

The headline number is a pure, documented function of its inputs — [`score.py`](src/endon_soc/score.py) —
so it is fully testable and never drifts from the tiles beneath it:

- start at 100, subtract a **super-linear weight per open finding** by severity (CRITICAL 25,
  HIGH 12, MEDIUM 5, LOW 1) so one CRITICAL outranks twenty LOWs — the score moves when
  something that can get you owned appears, not when a linter nitpicks;
- subtract a fixed penalty for every **disabled detective control**, because being blind is
  itself a risk. A green score sitting on top of a switched-off GuardDuty is exactly the false
  comfort this dashboard exists to prevent, so [`health.py`](src/endon_soc/health.py) probes
  GuardDuty, Security Hub, CloudTrail and Config, and feeds the count of blind spots back in.

Every deducted point traces to a specific finding or a specific blind spot — the board shows
the arithmetic (`-60 findings, -12 blind spots`), never a black box. The score fails safe: a
detector whose state can't be confirmed is treated as a blind spot, never as coverage.

## Read-only by construction

The SOC observes; it never contains, remediates or writes back — that boundary is a security
control, not tidiness. [`service.py`](src/endon_soc/service.py) exposes only reads, the API has
no mutating verb, and the deploy role has **read-only** access to the two DynamoDB tables
(`grant_read_data` — get/query/scan, never put or delete). A dashboard that cannot write cannot
be turned into a weapon by whoever reaches it. The infrastructure test enforces this.

## Authenticated by construction

Every route sits behind an **Amazon Cognito** user pool (MFA required, no self-sign-up). The
platform's weakest points are exactly what this console displays, so it is never served
unauthenticated. The infrastructure test asserts that every API Gateway method carries the
Cognito authorizer.

## How it connects to the platform

| Direction | Contract |
|---|---|
| Reads | The incident and finding tables via `endon_core.store` (the same records Projects 1-5 write) |
| Shows | Output of every component: incidents (1), IAM risk (2), posture (3), forensics evidence (4), data protection (5) |
| Depends on nothing at runtime but | `endon_core`, FastAPI, Jinja2, boto3 |

The [`demo`](src/endon_soc/demo.py) seeds the stores with a representative snapshot of all of
that, so the whole platform can be seen through the SOC offline, with no AWS account.

## Deployment

[`infrastructure/soc_stack.py`](infrastructure/soc_stack.py) provisions a Cognito user pool, an
API Gateway REST API with a Cognito authorizer on every method, and a single Lambda running the
FastAPI app with read-only access to the tables (and read-only detective-service calls for the
health panel). The Lambda runs the ASGI app through a small **dependency-free adapter**
([`lambda_handler.py`](src/endon_soc/lambda_handler.py)) — no ASGI framework in the bundle,
keeping the platform's dependency discipline, and the adapter is itself unit-tested.

```bash
cdk deploy EndonPlatform EndonSoc
```

## Security Decisions

1. **Read-only is a boundary, not a convention.** No write path in the code, and read-only IAM
   on the tables, verified by the synth test. The console cannot become an attacker's tool.
2. **Never serve the map of your weaknesses unauthenticated.** Cognito on every route, MFA
   required, no self-sign-up.
3. **The score must be explainable.** A pure function with published weights; every point of
   deduction is attributable. Security teams distrust a number they can't take apart.
4. **A green board on a blind detector is a lie.** Detective-control health is part of the
   score, and unconfirmed coverage counts against you, not for you.
5. **Keep the dependency footprint small.** A hand-written ASGI adapter instead of pulling a
   framework into the Lambda — less to trust, and it runs on the runtime's boto3 alone.

## Limitations

- **The score is a heuristic, deliberately simple.** Fixed severity weights make it explainable
  and stable; it is a triage signal, not a risk-quantification model. The weights live in one
  place and are easy to tune.
- **Health probes are point-in-time and region-scoped** to the Lambda's region. Org-wide
  coverage is a landing-zone concern (Project 6); here the panel reflects the account it runs in.
- **The store is a scan.** Listing reads the whole table (bounded by a limit); at very high
  finding volumes this would move to a query with a severity/time index. For the platform's
  scale a scan is correct and simplest.

## Lessons Learned

- **A dashboard is a security surface.** The most important decisions here were subtractive —
  no write path, no unauthenticated route — not features.
- **An explainable number beats an impressive one.** Making every deducted point traceable to a
  finding was worth more than any weighting cleverness; it's what makes the score usable.
- **You can adapt ASGI to Lambda in forty lines.** Writing the adapter instead of importing one
  kept the bundle honest and turned a deployment detail into a tested artifact.

## Run It

```bash
python 08-security-operations-center/attack-simulation/soc_walkthrough.py  # the offline board + HTML
pytest 08-security-operations-center/tests tests/test_soc_infrastructure.py  # tests
endon-soc demo                                                             # the board from the sample snapshot
endon-soc serve --demo                                                     # run the web console locally (needs uvicorn)
cdk deploy EndonPlatform EndonSoc                                          # deploy Cognito + API + Lambda
```

## Project Layout

```text
08-security-operations-center/
├── README.md · CASE_STUDY.md · SECURITY.md
├── architecture/{architecture.md, threat-model.md}
├── src/endon_soc/
│   ├── score.py          the security score (pure, explainable) - the flagship
│   ├── health.py         detective-control health probes (fail-safe)
│   ├── service.py        read-only read-model over the platform stores
│   ├── app.py            FastAPI app factory (REST API + server-rendered console)
│   ├── lambda_handler.py dependency-free ASGI -> Lambda adapter
│   ├── render.py         autoescaped Jinja2 environment
│   ├── demo.py           a platform-wide sample snapshot
│   ├── report.py / cli.py / wiring.py
│   └── templates/{base,dashboard,incident}.html
├── infrastructure/soc_stack.py   Cognito + API Gateway + read-only Lambda
├── attack-simulation/soc_walkthrough.py
├── evidence/
└── tests/
```
