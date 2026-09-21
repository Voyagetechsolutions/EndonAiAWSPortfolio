# Evidence

| Evidence | Source | Status |
|---|---|---|
| [`pipeline-check.txt`](pipeline-check.txt) | Offline OIDC-trust + blast-radius proof (5/5 assume denials, 6/6 action denials) | Captured |
| `pipeline-check-console.png` | Terminal output of `compromised_pipeline.py` | To capture |
| `oidc-provider.png` | The GitHub OIDC identity provider in the IAM console | To capture |
| `deploy-role-trust.png` | The deploy role's trust policy showing the `sub`/`aud` conditions | To capture |
| `deploy-role-boundary.png` | The permissions boundary attached to the deploy role | To capture |
| `actions-run.png` | A green GitHub Actions run assuming the role with no stored AWS keys | To capture |
| `denied-fork-run.png` | A fork / feature-branch run failing to assume the role (`Not authorized`) | To capture |

## Capturing live evidence

1. Run `python 07-github-oidc-cicd/attack-simulation/compromised_pipeline.py`; screenshot the proof.
2. Deploy the stack (`cd 07-github-oidc-cicd/infrastructure && cdk deploy`). Screenshot the
   OIDC provider, and the deploy role's trust policy and permissions boundary in the IAM console.
3. Push to `main` and capture the green Actions run — note the job has `id-token: write` and
   **no** `AWS_ACCESS_KEY_ID` secret; credentials come from OIDC.
4. Open a pull request (or push from a fork) and capture the deploy job failing at the
   `configure-aws-credentials` step, proving the trust conditions hold in production.
5. Redact the account ID before publishing.
