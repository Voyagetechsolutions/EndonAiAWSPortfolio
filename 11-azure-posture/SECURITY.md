# Security Notes: Azure Posture Scanner

See the repository-wide [SECURITY.md](../SECURITY.md) for vulnerability reporting.

## Operating notes

- **The checks are read-only.** They evaluate resource JSON and emit findings; they never change
  an Azure resource.
- **Least privilege for live collection.** `endon-azure scan --live` needs only *read* over the
  subscription — the built-in **Reader** role plus **Security Reader** is enough for Resource
  Graph and Defender pricing. Do not grant it Contributor.
- **Credentials come from the environment.** The collector uses `DefaultAzureCredential`
  (`az login`, a managed identity, or a service principal via env vars). No secrets are stored by
  this project; keep the service principal scoped to Reader and rotate it like any credential.
- **The gate blocks on HIGH+.** `--fail-on HIGH` fails on HIGH and CRITICAL; MEDIUM findings are
  reported. Loosening it is a deliberate, reviewable risk decision.

## Scope and blind spots

- **Inventory snapshot, not continuous.** It scans the resources at query time. Continuous
  evaluation is Microsoft Defender for Cloud's job — which control AZ-DEF-001 checks is enabled.
- **Resource properties, per-resource.** Posture that spans resources (a private endpoint or a
  policy assignment in a separate resource) isn't fully modelled here.
- **9 curated controls,** not exhaustive Azure coverage.

## Using it

```bash
# From an export (no SDK needed):
az graph query -q "Resources | project id,name,type,location,resourceGroup,properties" -o json > resources.json
endon-azure scan resources.json --fail-on HIGH

# Live (Reader/Security Reader):
pip install 'endon-azure[live]'
az login
endon-azure scan --live --subscription <subscription-id> --fail-on HIGH
```
