"""Render Endon findings as SARIF 2.1.0 — the OASIS static-analysis interchange format.

Every Endon scanner already speaks ASFF (see :meth:`Finding.to_asff`) so findings
land in AWS Security Hub. SARIF is the other half of that story: it is the format
GitHub code scanning, Azure DevOps, GitLab and the VS Code SARIF viewer ingest, so
the same finding that opens a Security Hub ticket in AWS can raise a code-scanning
alert in the pull request that introduced it. One finding model, two industry formats.

The mapping:

* one SARIF ``run`` per scan, tagged with the tool name and this repo's URL;
* one ``rule`` per distinct control, carrying its remediation as ``help`` text and a
  GitHub ``security-severity`` score so the alert inherits the right severity;
* one ``result`` per finding, its resources recorded as ``logicalLocations`` (Endon
  findings describe cloud resources and plan entries, which have no source line), and
  the finding's stable fingerprint as a ``partialFingerprint`` so a consumer can track
  the same issue across runs.
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterable
from typing import Any

from endon_core.findings import Finding, Severity

SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/sarif-2.1/schema/sarif-schema-2.1.0.json"
REPO_URL = "https://github.com/Voyagetechsolutions/EndonAiAWSPortfolio"

# SARIF result levels are coarser than Endon's five severities.
_LEVEL: dict[Severity, str] = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFORMATIONAL: "note",
}

_NON_ALNUM = re.compile(r"[^0-9A-Za-z]+")


def _rule_name(finding_type: str) -> str:
    """An opaque, stable rule name (SARIF wants an identifier, not a sentence)."""
    return _NON_ALNUM.sub("", finding_type.title()) or "EndonRule"


def _security_severity(severity: Severity) -> str:
    """GitHub's 0.0-10.0 ``security-severity`` string, derived from the ASFF score."""
    return f"{severity.normalized / 10:.1f}"


def _rule_id(finding: Finding) -> str:
    return finding.control_id or finding.type


def _rule(finding: Finding) -> dict[str, Any]:
    tags = ["security", finding.type.split(":", 1)[0].lower()]
    if finding.domain is not None:
        tags.append(finding.domain.value)
    rule: dict[str, Any] = {
        "id": _rule_id(finding),
        "name": _rule_name(finding.type),
        "shortDescription": {"text": finding.title},
        "fullDescription": {"text": finding.description or finding.title},
        "helpUri": REPO_URL,
        "defaultConfiguration": {"level": _LEVEL[finding.severity]},
        "properties": {"security-severity": _security_severity(finding.severity), "tags": tags},
    }
    if finding.remediation:
        rule["help"] = {"text": finding.remediation}
    return rule


def _locations(finding: Finding) -> list[dict[str, Any]]:
    if not finding.resources:
        return []
    return [
        {
            "logicalLocations": [
                {"fullyQualifiedName": r.id, "name": r.name, "kind": r.type}
                for r in finding.resources
            ]
        }
    ]


def _result(finding: Finding) -> dict[str, Any]:
    result: dict[str, Any] = {
        "ruleId": _rule_id(finding),
        "level": _LEVEL[finding.severity],
        "message": {"text": finding.description or finding.title},
        "partialFingerprints": {"endonFindingId/v1": finding.id},
        "properties": {"severity": finding.severity.value, "endon/type": finding.type},
    }
    locations = _locations(finding)
    if locations:
        result["locations"] = locations
    return result


def to_sarif(
    findings: Iterable[Finding],
    *,
    tool_name: str,
    tool_version: str = "0.1.0",
    information_uri: str = REPO_URL,
) -> dict[str, Any]:
    """Build a SARIF 2.1.0 log for one scan. Rules are derived from the findings present."""
    findings = list(findings)

    rules: dict[str, dict[str, Any]] = {}
    for finding in findings:
        rules.setdefault(_rule_id(finding), _rule(finding))

    return {
        "version": "2.1.0",
        "$schema": SCHEMA,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": tool_name,
                        "version": tool_version,
                        "informationUri": information_uri,
                        "rules": list(rules.values()),
                    }
                },
                "results": [_result(f) for f in findings],
            }
        ],
    }


def render_sarif(findings: Iterable[Finding], *, tool_name: str, **kwargs: Any) -> str:
    """Convenience: :func:`to_sarif` serialized to an indented JSON string."""
    return json.dumps(to_sarif(findings, tool_name=tool_name, **kwargs), indent=2)
