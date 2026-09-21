# Threat Model: Passwordless CI/CD (OIDC)

## Scope

The deployment path from GitHub Actions to AWS: the OIDC trust, the deploy role's identity
policy, and its permissions boundary. This project's job is to make CI credentials
non-leakable and to bound what a deploy — legitimate or compromised — can do.

## Assets

| Asset | Why it matters |
|---|---|
| AWS deploy credentials | Grant the ability to change production infrastructure |
| The trust relationship | Whoever satisfies it can deploy as the platform |
| IAM (users, keys, policies) | The path from "deploy access" to "own the account" |
| Customer data (S3, DynamoDB, KMS) | The destruction target if a deploy turns hostile |
| The Endon platform's own resources | The pipeline is the one identity allowed to change them (Project 6 exempts it) |

## Attackers

| Attacker | Position | Goal |
|---|---|---|
| Key thief | Exfiltrated a CI credential (leaked secret, compromised action, log) | Use it later from anywhere |
| Untrusted contributor | Opens a PR, or pushes from a fork | Trigger a deploy / assume the role |
| Compromised pipeline | Full control of a run on `main` | Escalate to account admin, establish persistence, destroy data |
| Branch/tag pusher | Can push a non-`main` ref | Assume the deploy role outside the review path |

## Threats and controls

| # | Threat | Control | Proven by |
|---|---|---|---|
| 1 | A leaked static AWS key used later | No static key exists; OIDC issues ~1h credentials per run | design (`deploy.yml` has no AWS secret) |
| 2 | A fork or different owner assumes the role | `sub` StringLike pins the exact `owner/repo` | `test_everything_other_than_main_is_denied` |
| 3 | A pull request assumes the role | `sub` for a PR is `...:pull_request`, not an allowed subject | `test_everything_other_than_main_is_denied` |
| 4 | A feature branch or tag assumes the role | `sub` carries the ref; only `refs/heads/main` matches | `test_everything_other_than_main_is_denied` |
| 5 | A token minted for another audience is replayed | `aud` StringEquals `sts.amazonaws.com` | `test_wrong_audience_is_denied` |
| 6 | Compromised pipeline creates an IAM user / access key (persistence) | boundary denies `iam:CreateUser`, `iam:CreateAccessKey` | `test_boundary_denies_privilege_escalation` |
| 7 | Compromised pipeline attaches admin to itself / passes a role | boundary denies `iam:Attach*Policy`, `iam:PutRolePolicy`, `iam:PassRole` | `test_boundary_denies_privilege_escalation` |
| 8 | Compromised pipeline deletes data | boundary denies `s3:DeleteBucket`, `dynamodb:DeleteTable`, `kms:ScheduleKeyDeletion` | `test_boundary_denies_destructive_data_actions` |
| 9 | Attacker widens the identity policy to `Allow *` | explicit `Deny` in the boundary still wins | `test_boundary_is_the_backstop_even_if_identity_is_widened` |
| 10 | A change regresses IAM or posture | pre-deploy IAM gate (Project 2) + post-deploy posture gate (Project 3) fail the build | `test_iam_gate_fails_on_a_critical_finding`, `test_posture_gate_fails_on_a_public_bucket` |

## Availability of legitimate operations (controls must not over-block)

| Requirement | Mechanism | Proven by |
|---|---|---|
| A push to `main` can deploy | `sub` for `refs/heads/main` is an allowed subject | `test_push_to_main_of_the_exact_repo_is_allowed` |
| Named environments can be allowed | `allowed_environments` add `...:environment:<name>` subjects | `test_environment_deployments_can_be_allowed_explicitly` |
| CDK can actually deploy | identity policy allows `sts:AssumeRole` on `cdk-*`; boundary allows the deployment surface | `test_deploy_role_can_assume_cdk_roles_and_nothing_else`, `test_boundary_allows_the_deployment_surface` |

## Residual risks

| Risk | Why it remains | Treatment |
|---|---|---|
| A malicious change is pushed *to `main`* by an authorized committer | The trust correctly allows `main`; this is a code-review / branch-protection problem, not a trust one | Require PR review + branch protection on `main`; the IAM/posture gates still bound the damage |
| The OIDC provider thumbprint / GitHub issuer changes | Federation depends on GitHub's issuer | AWS manages the GitHub OIDC thumbprint; monitor GitHub's OIDC announcements |
| The account is not CDK-bootstrapped, or bootstrap roles are over-broad | The deploy role assumes the CDK roles, whose power is set at bootstrap | Bootstrap with scoped policies; bootstrap is a one-time admin step outside the pipeline |
| A dependency compromises a *non-deploy* job | Only the deploy job has `id-token: write` | Keep `id-token` off other workflows; least-privilege `GITHUB_TOKEN` |
