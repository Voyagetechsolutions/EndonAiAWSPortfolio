# Threat Model: Security Operations Center

## Scope

The read-only web console and REST API over the platform's incident and finding stores, and the
Cognito-gated infrastructure that serves it. The SOC's own risk is that it aggregates, in one
place, the full picture of the platform's weaknesses and its response tooling — so the threats
are about that aggregation being read, abused, or turned into an action path.

## Assets

| Asset | Why it matters |
|---|---|
| The aggregated exposure picture | The complete map of the platform's current weaknesses |
| The incident and finding tables | The system of record the SOC reads |
| The deploy identity | If it could write, it would be a privileged foothold |
| Operator access (Cognito) | Whoever holds it sees everything the SOC shows |

## Attackers

| Attacker | Position | Goal |
|---|---|---|
| Unauthenticated web attacker | Can reach the API/console URL | Read the exposure map without credentials |
| Compromised operator session | A valid Cognito session | Pivot from "view" to "act on the platform" |
| Malicious finding content | Controls a scanned resource's name/description | Inject markup/script into the console (stored XSS) |
| Curious insider | Read access to the console | Use it to change or delete platform state |

## Threats and controls

| # | Threat | Control | Proven by |
|---|---|---|---|
| 1 | Read the exposure map with no credentials | Cognito authorizer on every API Gateway method | `test_every_api_route_is_cognito_authenticated` |
| 2 | Turn the console into a write path (create/alter/delete records) | No mutating verb in the API; read-only IAM on the tables | `test_api_is_read_only_no_mutating_verbs`, `test_console_cannot_write_the_platform_tables` |
| 3 | Escalate from the SOC role to broader account access | Only read-only table access, read-only health probes, `kms:Decrypt` | `test_detective_health_permissions_are_read_only` |
| 4 | Stored XSS via a crafted resource name in a finding | Autoescaped Jinja2 environment; API returns JSON, never executes content | `test_incident_page_renders_and_escapes` |
| 5 | A weak or shared operator login | Cognito MFA required, self-sign-up disabled | `test_a_cognito_user_pool_gates_access` |
| 6 | A false-green board hiding a disabled detector | Blind detectors penalize the score; unconfirmed = blind | `test_disabled_detectors_penalize_the_score`, `test_probe_never_raises_and_enabling_reduces_blind_spots` |

## Availability / correctness of the view (the SOC must not mislead)

| Requirement | Mechanism | Proven by |
|---|---|---|
| The score is explainable and stable | Pure function with published weights; deductions reported | `test_every_point_deducted_traces_to_a_finding` |
| Severity dominates volume | Super-linear weights | `test_one_critical_outweighs_a_pile_of_lows` |
| A clean account reads 100/A | Zero findings, zero blind spots | `test_a_clean_account_scores_100_grade_a` |
| Incidents show their full timeline | `GET /api/incidents/{id}` returns actions + timeline | `test_incident_detail_has_timeline_and_404s` |

## Residual risks

| Risk | Why it remains | Treatment |
|---|---|---|
| A compromised operator can *read* everything | That is the console's purpose; auth limits who, not what | MFA, invite-only, short Cognito token lifetimes; audit sign-ins |
| The score is a heuristic, not a risk model | Fixed weights favour explainability over precision | Documented as advisory; weights centralized and tunable |
| Health is point-in-time and region-scoped | Probes reflect the Lambda's account/region | Org-wide guarantees are Project 6's job (SCPs); the panel is a live check, not the control |
| A very large finding volume scans the table | Listing reads the whole table (bounded by a limit) | A severity/time index + query if scale demands; a scan is correct at platform scale |
