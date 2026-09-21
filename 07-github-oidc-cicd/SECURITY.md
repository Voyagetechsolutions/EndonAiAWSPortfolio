# Security Notes: Passwordless CI/CD (OIDC)

See the repository-wide [SECURITY.md](../SECURITY.md) for vulnerability reporting.

## Operating notes

- **No AWS keys in GitHub.** The whole point is that there is nothing static to leak. Do not
  add `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` to repository secrets — only the non-secret
  variables `AWS_DEPLOY_ROLE_ARN` and `AWS_REGION`. If a stored AWS key ever appears, the
  federation is being bypassed.
- **The `sub` condition is the control.** Trust is pinned to `repo:<owner>/<repo>:ref:refs/heads/main`.
  Never relax it to a wildcard `sub` (e.g. `repo:<owner>/<repo>:*`) — that would trust every
  branch and every pull request, which is the most common OIDC misconfiguration. Widening the
  deploy branches is a deliberate change to `deploy_branches` in the stack.
- **`id-token: write` belongs only on the deploy workflow.** That permission lets a job mint an
  OIDC token. Grant it at the job level, not repository-wide, and keep it off workflows that
  run untrusted code (e.g. PRs from forks).
- **The permissions boundary is load-bearing.** `EndonDeployBoundary` is what contains a
  compromised pipeline. Treat any change to its deny list like a production change and re-run
  the boundary tests; never detach it "to unblock a deploy" — widen the identity policy within
  the boundary instead.
- **Least privilege for `GITHUB_TOKEN`.** The workflow sets `contents: read`; keep it minimal
  so a compromised step cannot rewrite the repository.

## Trust conditions in force

| Claim | Operator | Value |
|---|---|---|
| `token.actions.githubusercontent.com:aud` | StringEquals | `sts.amazonaws.com` |
| `token.actions.githubusercontent.com:sub` | StringLike | `repo:mthokozisi-chaza/endon-ai:ref:refs/heads/main` (and any configured environments) |

A run whose token does not match both conditions is refused by AWS STS, before any workflow
step touches the account.

## What the boundary denies

Even with an over-permissive identity policy, the deploy role cannot: create IAM users or
login profiles, create access keys, attach or put user/role policies, create policy versions,
pass roles, alter its own permissions boundary, act on `organizations:*` or `account:*`, or
delete S3 buckets / DynamoDB tables / schedule KMS key deletion. See
[`boundary.py`](src/endon_pipeline/boundary.py) for the authoritative list.

## Rolling out safely

1. Bootstrap the target account for CDK (`cdk bootstrap`) — a one-time admin step.
2. Deploy this stack to create the OIDC provider, the boundary, and the deploy role.
3. Set `AWS_DEPLOY_ROLE_ARN` and `AWS_REGION` as repository variables (not secrets).
4. Verify with a push to `main` (should deploy) and a pull request (should fail at
   `configure-aws-credentials`) before removing any old long-lived deploy key.
