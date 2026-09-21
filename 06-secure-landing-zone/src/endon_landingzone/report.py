"""Governance report: the OU tree, SCP attachments, and the guardrail simulation matrix."""

from __future__ import annotations

import json
from dataclasses import dataclass

from endon_landingzone.baseline import BASELINE
from endon_landingzone.organization import Organization, OrgUnit, build_endon_organization
from endon_landingzone.simulator import Request, ScpSimulator

# The dangerous actions the guardrail matrix proves are blocked for a workload admin.
GUARDRAIL_CHECKS = [
    ("Stop CloudTrail logging", "cloudtrail:StopLogging", "us-east-1", None),
    ("Delete the CloudTrail trail", "cloudtrail:DeleteTrail", "us-east-1", None),
    ("Stop the Config recorder", "config:StopConfigurationRecorder", "us-east-1", None),
    ("Disable GuardDuty", "guardduty:DeleteDetector", "us-east-1", None),
    ("Disable Security Hub", "securityhub:DisableSecurityHub", "us-east-1", None),
    ("Remove account Block Public Access", "s3:PutAccountPublicAccessBlock", "us-east-1", None),
    ("Make a bucket public (ACL)", "s3:PutBucketAcl", "us-east-1", {"s3:x-amz-acl": "public-read"}),
    ("Operate in an unapproved region", "ec2:RunInstances", "ap-southeast-2", None),
    ("Modify the Endon response engine", "lambda:UpdateFunctionCode", "us-east-1", None),
    ("Leave the organization", "organizations:LeaveOrganization", "us-east-1", None),
]

WORKLOAD_ADMIN = "arn:aws:iam::222222222222:role/Admin"
ENDON_FUNCTION = "arn:aws:lambda:us-east-1:222222222222:function:EndonResponseEngine"


@dataclass
class GuardrailResult:
    description: str
    action: str
    denied: bool
    denied_by: str | None


def evaluate_guardrails(org: Organization, ou: str = "Production") -> list[GuardrailResult]:
    simulator = ScpSimulator(org.effective_scps(ou))
    results = []
    for description, action, region, context in GUARDRAIL_CHECKS:
        resource = ENDON_FUNCTION if action.startswith("lambda:") else "*"
        decision = simulator.evaluate(
            Request(
                action=action,
                principal_arn=WORKLOAD_ADMIN,
                region=region,
                resource=resource,
                context=context or {},
            )
        )
        results.append(
            GuardrailResult(description, action, not decision.allowed, decision.denied_by)
        )
    return results


def render_console(org: Organization | None = None) -> str:
    org = org or build_endon_organization()
    lines = ["ENDON AI - SECURE LANDING ZONE", "=" * 30, "", "ORGANIZATION"]
    lines.extend(_tree(org.root, org))

    lines += ["", "SECURITY BASELINE", "-" * 17]
    for control in BASELINE:
        admin = " (delegated admin: Security Tooling)" if control.delegated_admin else ""
        lines.append(
            f"  [{control.scs_c03_domain}] {control.service}: {control.description}{admin}"
        )

    lines += ["", "GUARDRAIL PROOF - a full admin in the Production account", "-" * 54]
    for result in evaluate_guardrails(org):
        mark = "DENIED " if result.denied else "ALLOWED"
        by = f"  <- {result.denied_by}" if result.denied_by else ""
        lines.append(f"  [{mark}] {result.description}{by}")
    denied = sum(1 for r in evaluate_guardrails(org) if r.denied)
    total = len(GUARDRAIL_CHECKS)
    lines.append(
        f"\n  {denied}/{total} dangerous actions blocked by SCP for a workload administrator."
    )
    return "\n".join(lines)


def render_json(org: Organization | None = None) -> str:
    org = org or build_endon_organization()
    return json.dumps(
        {
            "organization": _tree_dict(org.root, org),
            "baseline": [c.__dict__ for c in BASELINE],
            "guardrail_proof": [
                {
                    "check": r.description,
                    "action": r.action,
                    "denied": r.denied,
                    "deniedBy": r.denied_by,
                }
                for r in evaluate_guardrails(org)
            ],
        },
        indent=2,
    )


def _tree(unit: OrgUnit, org: Organization, depth: int = 1) -> list[str]:
    indent = "  " * depth
    scps = ", ".join(scp.name for scp in org.scps_for_ou(unit.name)) or "-"
    lines = [f"{indent}{unit.name}  [SCPs: {scps}]"]
    for account in unit.accounts:
        lines.append(f"{indent}  * account {account.name}: {account.purpose}")
    for child in unit.children:
        lines.extend(_tree(child, org, depth + 1))
    return lines


def _tree_dict(unit: OrgUnit, org: Organization) -> dict:
    return {
        "ou": unit.name,
        "scps": [scp.id for scp in org.scps_for_ou(unit.name)],
        "accounts": [{"name": a.name, "purpose": a.purpose} for a in unit.accounts],
        "children": [_tree_dict(child, org) for child in unit.children],
    }
