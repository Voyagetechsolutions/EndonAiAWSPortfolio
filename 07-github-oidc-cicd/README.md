# Project 7 · Passwordless GitHub → AWS CI/CD (OIDC)

> Part of the [Endon AI](../README.md) platform · **Status: built and tested** · GitHub OIDC federation + IAM permissions boundary (CDK)

The deployment layer for the whole platform. It replaces long-lived AWS access keys in
GitHub with **OIDC federation** — GitHub Actions exchanges a short-lived identity token for
temporary AWS credentials — and it caps what a deploy can do with a **permissions boundary**,
so a compromised pipeline cannot escalate privilege or destroy data. Both claims are proven
by the same engines the tests assert against.

---

## The Security Problem

CI/CD is a standing set of production credentials. The usual pattern — an
`AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` for a deploy user, stored in GitHub secrets —
has two failure modes that keep showing up in real breaches:

1. **The key leaks and never expires.** A long-lived key in CI can be exfiltrated through a
   malicious dependency, a compromised action, or a logging mistake, and it stays valid until
   someone notices and rotates it.
2. **The deploy identity is over-powered.** Deploy users are routinely granted broad IAM so
   the pipeline "just works", which means whoever controls the pipeline controls the account —
   they can create a backdoor user, mint access keys, or attach `AdministratorAccess`.

**Goal:** no long-lived keys anywhere, trust scoped to exactly one repository and branch, and
a hard ceiling on the blast radius even if the pipeline is fully compromised.

## The two controls

### 1. Keyless trust (who can deploy)

There are no AWS keys in GitHub. Instead the AWS account has a **GitHub OIDC identity
provider**, and the deploy role trusts it through `sts:AssumeRoleWithWebIdentity` with two
conditions on the GitHub-issued token:

- `...:aud` **StringEquals** `sts.amazonaws.com` — the token was minted for AWS STS, and
- `...:sub` **StringLike** `repo:mthokozisi-chaza/endon-ai:ref:refs/heads/main` — it came
  from a push to `main` of *this exact repository*.

A fork, a feature branch, a pull request, a tag, or any other repository produces a different
`sub` claim and is refused by STS. The token is valid for minutes, not forever.

[`oidc.py`](src/endon_pipeline/oidc.py) builds that trust policy and models the token claims;
`GitHubOidcConfig.allowed_subjects()` is the single source of truth for what `sub` values are
allowed, used both by the CDK stack and by the simulator.

### 2. A permissions boundary (what a deploy can do)

The deploy role's identity policy grants only `sts:AssumeRole` on the CDK bootstrap roles —
that is all CDK needs. On top of that, a customer-managed **permissions boundary** caps the
role: it allows the deployment surface (CloudFormation, S3, STS, SSM, ECR) and **explicitly
denies** the privilege-escalation and data-destruction actions — `iam:CreateUser`,
`iam:CreateAccessKey`, `iam:AttachUserPolicy`, `iam:PutRolePolicy`, `iam:PassRole`,
`organizations:*`, `s3:DeleteBucket`, `kms:ScheduleKeyDeletion`, and more.

Because an explicit `Deny` wins, this holds **even if the identity policy is widened to
administrator** — which is exactly what a compromised pipeline would try to do.
[`boundary.py`](src/endon_pipeline/boundary.py) builds both policies and the
`DeployRoleModel` that evaluates them together (`.can(action, resource)` is allowed only when
the identity policy *and* the boundary both allow it).

## The proof (the flagship)

[`compromised_pipeline.py`](attack-simulation/compromised_pipeline.py) red-teams both controls
offline — no AWS account needed — using the same `oidc.py` and `boundary.py` engines the tests
assert against, so the demo and the proof never drift.

```bash
python 07-github-oidc-cicd/attack-simulation/compromised_pipeline.py
```

```text
WHO CAN ASSUME THE DEPLOY ROLE (GitHub OIDC trust)
-------------------------------------------------
  [ALLOWED] Push to main of our repo
  [DENIED ] Push to a feature branch
  [DENIED ] A pull request
  [DENIED ] A fork / different owner
  [DENIED ] A different repository
  [DENIED ] A git tag

BLAST RADIUS OF A COMPROMISED PIPELINE (deploy role + boundary)
--------------------------------------------------------------
  [ALLOWED] Assume the CDK deploy role
  [DENIED ] Create an IAM user (persistence)
  [DENIED ] Create an access key
  [DENIED ] Attach AdministratorAccess to itself
  [DENIED ] Pass a privileged role
  [DENIED ] Delete an S3 bucket (destroy data)
  [DENIED ] Leave the organization

  5/5 unauthorized assume attempts denied.
  6/6 dangerous pipeline actions denied.
```

Those outcomes are asserted in [`test_oidc_trust.py`](tests/test_oidc_trust.py) and
[`test_boundary.py`](tests/test_boundary.py) — including the key case that the boundary
contains the role *even when its identity policy is replaced with `Allow *`*.

## The pipeline runs Endon's own scanners as gates

The deploy is not just keyless and bounded — it also refuses to ship an insecure change. The
workflow calls two gates built from earlier projects:

- **Pre-deploy IAM gate** — runs **Project 2**'s IAM analyzer against the account and fails the
  build on any `CRITICAL` finding (an admin-equivalent principal, a privilege-escalation path).
- **Post-deploy posture gate** — runs **Project 3**'s posture scanner and fails on any `HIGH`
  misconfiguration (a public bucket, an open security group).

[`gate.py`](src/endon_pipeline/gate.py) wraps both as `GateResult`s and
[`cli.py`](src/endon_pipeline/cli.py) exposes them as `endon-pipeline gate --iam|--posture`,
exiting non-zero to break the build. The pipeline that deploys the platform is guarded by the
platform.

## Infrastructure

[`infrastructure/pipeline_stack.py`](infrastructure/pipeline_stack.py) deploys the
`iam.OpenIdConnectProvider` for `token.actions.githubusercontent.com`, the
`EndonDeployBoundary` managed policy, and the `EndonDeploy-github-actions` role trusting the
provider with the `aud`/`sub` conditions and carrying the boundary. The
[infrastructure test](../tests/test_pipeline_infrastructure.py) synthesizes the stack and
asserts the provider, the web-identity trust conditions, the attached boundary, the denied
escalation actions, and that the identity policy grants nothing but `sts:AssumeRole`.

```bash
cd 07-github-oidc-cicd/infrastructure
cdk deploy -c endon:githubOwner=mthokozisi-chaza -c endon:githubRepo=endon-ai
```

The reference workflow is [`.github/workflows/deploy.yml`](.github/workflows/deploy.yml): it
requests `id-token: write`, exchanges the OIDC token via
`aws-actions/configure-aws-credentials@v4` (`role-to-assume: ${{ vars.AWS_DEPLOY_ROLE_ARN }}`),
runs the IAM gate, `cdk synth`/`deploy`, then the posture gate — with **no** AWS secret in the
repository.

## Security Decisions

1. **No long-lived keys, ever.** Federated OIDC tokens are minutes-long and minted per run.
   There is nothing in GitHub secrets to leak.
2. **Trust the smallest possible thing.** The `sub` condition pins trust to one repo and one
   branch. Everything else — forks, PRs, tags, other repos — is a different subject and is
   denied by STS, not by a later check.
3. **Assume the pipeline will be compromised.** The permissions boundary is designed to hold
   when the identity policy is wrong, because that is the realistic failure. Deny-wins is the
   only ceiling that survives an over-powered identity.
4. **Gate on your own evidence.** The deploy runs Projects 2 and 3 as blocking gates, so a
   change that would regress IAM or posture cannot reach production.
5. **Prove it.** Both controls are a passing test and the same engine drives the evidence.

## Limitations

- **The trust simulator models the `sub`/`aud` conditions**, which is where OIDC federation is
  actually secured. It does not re-implement STS token validation (signature, issuer, expiry) —
  that is AWS's job; the stack wires the real provider.
- **The boundary model evaluates IAM `Allow`/`Deny` for the deploy role and its boundary.** It
  is not a full IAM policy simulator (that is Project 2); it evaluates the two policies that
  determine this role's blast radius.
- **`cdk deploy` still needs a bootstrapped account** with the CDK roles the deploy role
  assumes. Bootstrapping is a one-time admin step, out of the pipeline's own scope.

## Lessons Learned

- **Keyless beats rotated.** The best way to stop a CI key from leaking is to not have one.
  OIDC turns "rotate the deploy key" into a non-problem.
- **The trust condition is the security boundary.** Getting the `sub` string exactly right —
  repo *and* ref — is the whole control; a `sub` of just `repo:owner/name:*` would trust every
  branch and every PR.
- **A boundary is worth more than a tight identity policy.** Identity policies drift and get
  widened "to unblock a deploy"; a deny-based boundary keeps meaning something after they do.

## Run It

```bash
python 07-github-oidc-cicd/attack-simulation/compromised_pipeline.py   # the trust + blast proof
pytest 07-github-oidc-cicd/tests tests/test_pipeline_infrastructure.py  # tests
endon-pipeline simulate                                                # same proof, via the CLI
endon-pipeline gate --iam --region us-east-1                           # pre-deploy IAM gate
cd 07-github-oidc-cicd/infrastructure && cdk deploy
```

## Project Layout

```text
07-github-oidc-cicd/
├── README.md · CASE_STUDY.md · SECURITY.md
├── architecture/{architecture.md, threat-model.md}
├── src/endon_pipeline/
│   ├── oidc.py        GitHub OIDC trust policy + token-claim model + simulator (the proof)
│   ├── boundary.py    identity policy + permissions boundary + DeployRoleModel (the proof)
│   ├── gate.py        pre/post-deploy security gates reusing Projects 2 and 3
│   ├── report.py / cli.py
├── infrastructure/{pipeline_stack.py, app.py, cdk.json}
├── .github/workflows/deploy.yml   reference keyless workflow
├── attack-simulation/compromised_pipeline.py
├── evidence/
└── tests/
```
