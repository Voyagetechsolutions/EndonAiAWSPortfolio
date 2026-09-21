# Security Notes: Security Operations Center

See the repository-wide [SECURITY.md](../SECURITY.md) for vulnerability reporting.

## Operating notes

- **The console is read-only, and must stay that way.** The Lambda has `grant_read_data` on the
  incident and finding tables — get/query/scan, never put/update/delete — and there is no
  write path in the application. If a future feature needs to write, it belongs in a separate,
  separately-authorized service, not here. The infrastructure test fails if a write action
  appears.
- **Never expose it unauthenticated.** Every route is behind a Cognito authorizer. Do not add a
  public route, and do not add CORS that would let an arbitrary origin call the API with a
  stolen token. The console shows the map of the platform's weaknesses; that is exactly what
  must not leak.
- **Cognito is invite-only with MFA.** Self-sign-up is disabled and MFA (OTP) is required.
  Operators are created by an administrator. Review the user pool's membership like a
  production access list.
- **Least privilege beyond the tables.** The only other permissions are read-only detective
  health probes (`guardduty:ListDetectors`, `securityhub:DescribeHub`,
  `cloudtrail:DescribeTrails`/`GetTrailStatus`, `config:DescribeConfigurationRecorderStatus`)
  and `kms:Decrypt` for the table key. Nothing else.
- **The score is advisory.** It is a triage heuristic with published weights
  ([`score.py`](src/endon_soc/score.py)), not a compliance measure. Tune the weights
  deliberately and keep them in that one place; the tests pin the arithmetic.

## Trust boundary

The SOC treats finding titles, descriptions and resource ids as untrusted data: they originate
from scanned AWS resources and are rendered through an **autoescaped** Jinja2 environment, so a
crafted resource name cannot inject markup into the console. The API returns them as JSON. The
SOC never executes or acts on their content.

## Deployment checklist

1. Deploy `EndonPlatform` first (it owns the tables and KMS key), then `EndonSoc`.
2. Create Cognito users for the operators; confirm MFA enrolment.
3. Verify an unauthenticated request to the API returns `401`.
4. Verify the console renders and that no control on it performs a write (there are none).
