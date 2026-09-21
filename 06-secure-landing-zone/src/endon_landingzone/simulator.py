"""An SCP evaluation engine, so the guardrails can be proven rather than assumed.

Given the SCPs that apply to an account (the union along root -> OU -> account) and a
request, it decides whether an explicit ``Deny`` blocks it. This is the mechanism behind
the evidence: a table showing that a full administrator in a workload account is still
denied the dangerous actions, while the security administrator and legitimate requests are
allowed.

Scope: SCP *deny* evaluation with the condition operators the guardrails use
(``ArnLike``/``ArnNotLike`` on aws:PrincipalArn, ``StringEquals``/``StringNotEquals`` on
aws:RequestedRegion, ``StringLike`` and ``StringEquals`` on other keys). SCP allow-lists
and IAM policies are out of scope — the guardrails are deny-based over the default
FullAWSAccess, which is what this models.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from fnmatch import fnmatchcase
from typing import Any


@dataclass(frozen=True)
class Request:
    """A candidate action to evaluate against the SCPs."""

    action: str
    principal_arn: str
    region: str = "us-east-1"
    resource: str = "*"
    context: dict[str, Any] = field(default_factory=dict)  # e.g. {"s3:x-amz-acl": "public-read"}


@dataclass(frozen=True)
class ScpDecision:
    allowed: bool
    denied_by: str | None = None  # SCP name
    sid: str | None = None
    reason: str = ""


class ScpSimulator:
    def __init__(self, scps) -> None:
        # Accept Scp objects or raw policy documents.
        self.policies = [(_name(s), _document(s)) for s in scps]

    def evaluate(self, request: Request) -> ScpDecision:
        for name, document in self.policies:
            for statement in document.get("Statement", []):
                if statement.get("Effect") != "Deny":
                    continue
                if self._matches(statement, request):
                    sid = statement.get("Sid", "")
                    return ScpDecision(
                        allowed=False,
                        denied_by=name,
                        sid=sid,
                        reason=f"denied by SCP {name} ({sid})",
                    )
        return ScpDecision(allowed=True, reason="no SCP denies this request")

    def is_denied(self, request: Request) -> bool:
        return not self.evaluate(request).allowed

    def _matches(self, statement: dict, request: Request) -> bool:
        return (
            self._matches_action(statement, request.action)
            and self._matches_resource(statement, request.resource)
            and self._matches_conditions(statement.get("Condition", {}), request)
        )

    @staticmethod
    def _matches_action(statement: dict, action: str) -> bool:
        if "Action" in statement:
            return any(
                fnmatchcase(action.lower(), p.lower()) for p in _as_list(statement["Action"])
            )
        if "NotAction" in statement:
            return not any(
                fnmatchcase(action.lower(), p.lower()) for p in _as_list(statement["NotAction"])
            )
        return False

    @staticmethod
    def _matches_resource(statement: dict, resource: str) -> bool:
        resources = _as_list(statement.get("Resource", "*"))
        if "*" in resources:
            return True
        return any(fnmatchcase(resource, pattern) for pattern in resources)

    def _matches_conditions(self, condition: dict, request: Request) -> bool:
        return all(
            self._matches_operator(operator, mapping, request)
            for operator, mapping in condition.items()
        )

    def _matches_operator(self, operator: str, mapping: dict, request: Request) -> bool:
        return all(
            self._matches_key(operator, key, _as_list(values), request)
            for key, values in mapping.items()
        )

    def _matches_key(self, operator: str, key: str, values: list[str], request: Request) -> bool:
        actual = self._context_value(key, request)
        if actual is None:
            # A missing condition key: string conditions on an absent key do not match,
            # except the "Not"/"IfExists" style which is satisfied when the key is absent.
            return operator.startswith("StringNot") or operator.startswith("ArnNot")
        if operator in ("StringEquals",):
            return actual in values
        if operator in ("StringNotEquals",):
            return actual not in values
        if operator in ("StringLike", "ArnLike"):
            return any(fnmatchcase(actual, pattern) for pattern in values)
        if operator in ("StringNotLike", "ArnNotLike"):
            return not any(fnmatchcase(actual, pattern) for pattern in values)
        raise ValueError(f"Unsupported SCP condition operator: {operator}")

    @staticmethod
    def _context_value(key: str, request: Request) -> str | None:
        if key == "aws:PrincipalArn":
            return request.principal_arn
        if key == "aws:RequestedRegion":
            return request.region
        return request.context.get(key)


def _as_list(value) -> list:
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def _name(scp) -> str:
    return getattr(scp, "name", None) or "policy"


def _document(scp) -> dict:
    return getattr(scp, "document", None) if hasattr(scp, "document") else scp
