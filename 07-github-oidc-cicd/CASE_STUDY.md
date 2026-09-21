# Case Study: A Deploy Key That Can't Leak and Can't Escalate

## Context

A team ships to AWS from GitHub Actions. To let the workflow deploy, someone created an IAM
user with broad permissions, generated an access key, and pasted it into the repository's
secrets as `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY`. It works. It has worked for two
years. Nobody has rotated it, and three former contractors' laptops have had it in their
`~/.aws` at some point.

Then a popular GitHub Action the workflow depends on is compromised. On the next run it reads
the environment and exfiltrates the AWS key. Because the key is long-lived, it is still valid
hours later. Because the deploy user is over-powered, the attacker uses it to create a new IAM
user, attach `AdministratorAccess`, and mint a fresh access key for persistence. The original
key can now be rotated all day; the attacker has their own.

## The two problems

1. **The credential is long-lived.** A static key in CI is a secret that never expires and
   lives in more places than anyone tracks. Its security depends on nobody ever leaking it —
   for years.
2. **The credential is over-powered.** Deploy identities accrete permissions because the fast
   way to unblock a failing deploy is to grant more. An identity that can deploy *and* manage
   IAM means whoever controls the pipeline controls the account.

## The fix: keyless trust, hard ceiling

Two moves, and neither is "rotate the key more often":

1. **Delete the key. Federate instead.** The AWS account trusts GitHub's OIDC provider. On
   each run GitHub mints a short-lived identity token; `configure-aws-credentials` exchanges
   it for temporary AWS credentials via `sts:AssumeRoleWithWebIdentity`. There is no static
   AWS secret in GitHub to steal, and the token is valid for minutes. Trust is pinned by the
   token's `sub` claim to **one repository and one branch** — a fork, a PR, or a feature
   branch produces a different subject and STS refuses it.
2. **Cap the blast radius with a permissions boundary.** The deploy role's identity policy
   grants only `sts:AssumeRole` on the CDK bootstrap roles. A customer-managed permissions
   boundary then *denies* the escalation and destruction actions outright — creating users,
   minting keys, attaching policies, passing roles, deleting buckets. Because an explicit
   `Deny` wins, this holds even if the identity policy is later widened to administrator.

## Proving it

A trust policy is easy to write and easy to get subtly wrong — the classic mistake is a `sub`
of `repo:owner/name:*`, which quietly trusts every branch and every pull request. So this
project red-teams both controls with the same engines the tests use:

```text
WHO CAN ASSUME THE DEPLOY ROLE (GitHub OIDC trust)
  [ALLOWED] Push to main of our repo
  [DENIED ] Push to a feature branch
  [DENIED ] A pull request
  [DENIED ] A fork / different owner
  [DENIED ] A different repository
  [DENIED ] A git tag

BLAST RADIUS OF A COMPROMISED PIPELINE (deploy role + boundary)
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

Replay the opening story against this: the leaked-key step never happens (there is no key),
and every persistence move the attacker made is denied by a boundary they cannot change.

## The pipeline guards the platform that guards it

The deploy is keyless and bounded — and it also refuses to ship an insecure change. Before it
deploys it runs **Project 2**'s IAM analyzer (fail on any `CRITICAL`), and after it deploys it
runs **Project 3**'s posture scanner (fail on any `HIGH`). The pipeline that ships the whole
Endon platform is itself gated by two of the platform's own tools. Project 6's landing zone
then exempts exactly this deploy role in the `protect-endon-platform` SCP — so the one
identity allowed to change the responder is the one proven here to be un-escalatable.

## Takeaways

- The most reliable way to stop a CI credential from leaking is to not have one. OIDC turns a
  years-long rotation liability into a per-run token.
- The security of federation lives entirely in the trust condition. Pinning `sub` to repo
  *and* ref is the control; everything else is detail.
- Assume the pipeline will be compromised and design the ceiling for that. A deny-based
  permissions boundary is the only thing that still means something after an identity policy
  has been widened "to make the deploy pass".
