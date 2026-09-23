# Improvements

A running log of platform-wide improvements — what changed, why, and how it's proven.
Each entry is a capability added across the whole platform through the shared
[`endon-core`](../endon-core/) contracts, not a one-off tweak to a single project.

---

## 2026-09 · SARIF output + continuous code scanning

**What.** Every offline scanner can now emit its findings as
[SARIF 2.1.0](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html) — the OASIS
static-analysis interchange format that GitHub code scanning, Azure DevOps, GitLab and the
VS Code SARIF viewer ingest. A repo-root GitHub Actions workflow runs all five scanners on
every push and pull request and uploads the results to the GitHub **Security** tab.

**Why.** The platform already spoke ASFF, so a finding could open a ticket in AWS Security
Hub. But the cheapest place to catch a misconfiguration is the pull request that introduces
it, and the standard surface for that is code scanning, which speaks SARIF — not ASFF. Adding
SARIF closes the loop: **one finding model, two industry formats.** The same public-bucket
finding that raises a Security Hub ticket in the account (ASFF) now also raises a code-scanning
alert on the PR (SARIF). It's the "shift-left" half of the detection story the job market keeps
asking for (GitHub Advanced Security, DevSecOps, policy-as-code in CI).

**How it's built (one place, not five).**

- [`endon_core.sarif`](../endon-core/src/endon_core/sarif.py) — a single renderer,
  `to_sarif(findings, tool_name=…)` / `render_sarif(…)`, that turns any list of
  `endon_core.Finding` into a valid SARIF log. It derives one SARIF `rule` per distinct
  control (carrying the remediation as `help` text and a GitHub `security-severity` score
  computed from the finding's ASFF-normalized severity), one `result` per finding (resources
  recorded as `logicalLocations`, since findings describe cloud resources and plan entries,
  not source lines), and the finding's stable fingerprint as a `partialFingerprint` so a
  consumer can track the same issue across runs. Because it sits next to `Finding.to_asff`,
  the two formats stay in lock-step — a producer that emits a `Finding` gets both for free.
- **`--sarif` on every scanner CLI** — `endon-tfscan`, `endon-k8s`, `endon-azure`,
  `endon-siem`, `endon-finops`. The flag prints SARIF to stdout while the gate's exit code is
  unchanged, so a CI step can redirect SARIF to a file *and* still fail on a blocking finding.
- [`tools/scan_all.py`](../tools/scan_all.py) — a consolidated runner that executes all five
  scanners over their committed example fixtures in one process and writes one `.sarif` file
  each. It's a reporting pass (always exits 0); the per-scanner CLIs remain the gates. Runs
  locally with no cloud account.
- [`.github/workflows/security-scan.yml`](../.github/workflows/security-scan.yml) — runs the
  lint + test suite, then runs `scan_all.py` and uploads the SARIF directory with
  `github/codeql-action/upload-sarif`. To turn it into a **merge gate** on real infrastructure,
  point a scanner at your actual plan/manifests and drop `continue-on-error` — the non-zero
  exit (`--fail-on HIGH`) then blocks the pull request.

**Scope.** Terraform (P9), Kubernetes (P10), Azure (P11), CloudTrail/SIEM (P12) and
FinOps (P13). Any producer that emits `endon_core.Finding` — including the AWS scanners in
projects 1–8 — can render SARIF the same way; the flag is wired into the five standalone
scanner CLIs first because those are the ones that gate a pipeline.

**Proof.**

- 8 new unit tests in [`endon-core/tests/test_sarif.py`](../endon-core/tests/test_sarif.py)
  cover the top-level shape, the severity → level/score mapping (error/warning/note), rule
  deduplication, resource → `logicalLocations`, findings without resources, an empty scan,
  and JSON validity.
- `python tools/scan_all.py` produces valid SARIF for all five scanners — **60 findings**
  across the example fixtures (Terraform 15, Kubernetes 19, Azure 9, CloudTrail 11,
  FinOps 6) — committed under [`evidence/sarif/`](../evidence/sarif/). The output is
  deterministic (fingerprints, not timestamps), so it's reviewable and diff-stable.
- The full suite stays green and `ruff check .` is clean.

**Design decisions.**

1. **Share the renderer, don't repeat it.** SARIF lives in `endon-core` beside ASFF so both
   formats are defined once and can't drift per project.
2. **`logicalLocations`, not fake file lines.** Endon findings are cloud resources and plan
   entries; inventing a `physicalLocation` (file + line) would be dishonest. Logical locations
   are valid SARIF and carry the real resource identifier.
3. **SARIF is a report; the CLI is still the gate.** `--sarif` and the consolidated runner
   surface findings; blocking a merge stays the job of `--fail-on` and a non-zero exit, wired
   explicitly in CI. Reporting and gating are separate concerns.
4. **Severity carried, not flattened.** GitHub's `security-severity` is derived from the same
   ASFF-normalized score the platform already uses, so an alert inherits the right colour
   instead of a hard-coded guess.
