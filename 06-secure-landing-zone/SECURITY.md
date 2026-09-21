# Security Notes: Secure Landing Zone

See the repository-wide [SECURITY.md](../SECURITY.md) for vulnerability reporting.

## Operating notes

- **Deploy in the management account** with trusted access enabled. This stack creates
  organization resources; nothing else should run in the management account.
- **Guard the management account.** It can change SCPs and the org structure, so it is the
  highest-value target. Enforce MFA, minimize who can access it, and use it only for org
  management.
- **Exemptions are load-bearing.** The `EndonSecurityAdmin` and `EndonBreakGlass` roles are
  exempt from the logging/detection guardrails, and `EndonDeploy*` from the platform
  guardrail. Keep these role names controlled — anyone who can assume them bypasses the
  corresponding guardrail. Review them like production credentials.
- **Test SCP changes with the simulator first.** Before changing a guardrail, run
  `endon-landing-zone report` (and the guardrail tests) to confirm the change still blocks
  what it should and still exempts what it must.

## Rolling out safely

SCPs apply immediately and can lock people out. Roll out to the Sandbox OU first, confirm
with the simulator and real testing, then Development, then Production. Keep a break-glass
role (exempt, tightly controlled, MFA-enforced) for recovery.

## Region allowlist

Approved regions are in [`config.py`](src/endon_landingzone/config.py). Adding a region is a
deliberate change: new AWS regions are denied until added, which is the intended default.
