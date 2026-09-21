# Threat Model: Secure Landing Zone

## Scope

The organization structure, the SCP guardrails, and the security baseline. The landing zone
is the control plane above the workload accounts; the primary attacker here is a privileged
principal *inside* an account.

## Assets

| Asset | Why it matters |
|---|---|
| Audit logging (org CloudTrail, Config) | The record of everything; the first thing an attacker silences |
| Detective services (GuardDuty, Security Hub, Macie) | The platform's eyes; disabling them blinds it |
| Data (S3) | Must not be made public |
| The Endon platform itself | The responder and its pipeline must survive account admins |
| The organization membership | An account leaving the org escapes every guardrail |

## Attackers

| Attacker | Position | Goal |
|---|---|---|
| Compromised / careless workload admin | Full IAM admin in a member account | Disable logging or detection, exfiltrate via public S3, operate in an unmonitored region |
| Compromised account root | Root credentials in a member account | Anything |
| Compromised Endon deploy pipeline | The CI/CD role | Modify the platform (this is why the pipeline is Project 7's hardened, keyless design) |

## Threats and guardrails

| # | Threat (by a workload admin) | Guardrail | Proven by |
|---|---|---|---|
| 1 | Stop / delete CloudTrail to hide activity | `protect-security-logging` | `test_workload_admin_is_denied_dangerous_actions` |
| 2 | Stop the Config recorder | `protect-security-logging` | same |
| 3 | Disable GuardDuty / Security Hub | `protect-detection-services` | same |
| 4 | Remove account Block Public Access | `prevent-public-s3` | same |
| 5 | Make a bucket public via ACL | `prevent-public-s3` (x-amz-acl) | `test_public_bucket_acl_is_denied` |
| 6 | Operate in an unmonitored region | `region-allowlist` | `test_region_allowlist_blocks_unapproved_region_but_allows_approved` |
| 7 | Disable the Endon responder | `protect-endon-platform` | `test_endon_platform_is_protected_from_workload_admin_but_not_the_pipeline` |
| 8 | Detach the account from the org to escape SCPs | `prevent-leaving-organization` | `test_workload_admin_is_denied_dangerous_actions` |
| 9 | Operate as the account root user | `deny-root-user` | `test_root_user_is_denied_everything` |

## Availability of legitimate operations (guardrails must not over-block)

| Requirement | Mechanism | Proven by |
|---|---|---|
| Break-glass / security operations still work | `aws:PrincipalArn` exemption for the security admin | `test_security_admin_is_exempt_from_logging_and_detection_guardrails` |
| The platform can still be deployed | deploy-pipeline exemption on `protect-endon-platform` | `test_endon_platform_is_protected_from_workload_admin_but_not_the_pipeline` |
| Global services keep working under the region lock | `NotAction` for global-service prefixes | `test_global_services_are_exempt_from_the_region_lock` |
| Normal workload actions are unaffected | denies are narrow and specific | `test_ordinary_actions_are_allowed` |

## Residual risks

| Risk | Why it remains | Treatment |
|---|---|---|
| The management account itself is compromised | The management account can change SCPs and the org | Minimize its use; MFA + strict access; it runs nothing but org management |
| Delegated-admin bootstrap is manual | Enabling org-wide GuardDuty/Config/Macie and delegated admin is a management-account operation | Documented in the baseline; scripted in the deploy path |
| SCP allow-list nuances | The simulator models denies, not allow-lists | The guardrails are deny-based by design; IAM analysis is Project 2 |
| A new region AWS launches | The allowlist denies it until added | Intentional — new regions are opt-in |
