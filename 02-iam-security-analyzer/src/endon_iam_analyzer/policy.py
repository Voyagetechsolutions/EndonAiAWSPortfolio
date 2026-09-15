"""A small but faithful IAM policy-evaluation engine.

IAM's real evaluation logic is: an explicit ``Deny`` always wins, otherwise access
needs a matching ``Allow``. This module implements that for the questions a security
analyzer asks: *can this principal perform this action, on any resource, without a
condition getting in the way?* Those three facts — allowed, on any resource,
conditional — are what separate a real privilege-escalation path from a scoped grant.

It deliberately does not resolve condition keys or policy variables. Conditions are
surfaced as "this grant is conditional" rather than evaluated, because the analyzer's
job is to flag *potential* over-permission for a human to judge, not to prove
exploitability.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from fnmatch import fnmatchcase
from typing import Any


def _as_tuple(value: Any) -> tuple[str, ...]:
    if value is None:
        return ()
    if isinstance(value, str):
        return (value,)
    return tuple(str(v) for v in value)


def _action_matches(pattern: str, action: str) -> bool:
    return fnmatchcase(action.lower(), pattern.lower())


def _resource_matches(pattern: str, resource: str) -> bool:
    # IAM treats the "*" and "?" in resource ARNs as wildcards and compares
    # case-sensitively; fnmatchcase matches that exactly.
    return fnmatchcase(resource, pattern)


@dataclass(frozen=True)
class Statement:
    """One normalized policy statement.

    ``Action``/``NotAction`` and ``Resource``/``NotResource`` are mutually exclusive
    in valid policies; both forms are represented so the smell of ``NotAction`` with
    ``Allow`` can be detected.
    """

    effect: str
    actions: tuple[str, ...] = ()
    not_actions: tuple[str, ...] = ()
    resources: tuple[str, ...] = ()
    not_resources: tuple[str, ...] = ()
    conditions: Mapping[str, Any] = field(default_factory=dict)
    principal: Any = None
    not_principal: Any = None
    sid: str | None = None

    @property
    def is_allow(self) -> bool:
        return self.effect.lower() == "allow"

    @property
    def has_condition(self) -> bool:
        return bool(self.conditions)

    def matches_action(self, action: str) -> bool:
        if self.actions:
            return any(_action_matches(p, action) for p in self.actions)
        if self.not_actions:
            return not any(_action_matches(p, action) for p in self.not_actions)
        return False

    def grants_on_any_resource(self) -> bool:
        # NotResource is treated as "any resource except a few" — still effectively broad.
        return "*" in self.resources or bool(self.not_resources)

    def matches_resource(self, resource: str) -> bool:
        if resource == "*":
            return self.grants_on_any_resource()
        if self.resources:
            return any(_resource_matches(p, resource) for p in self.resources)
        if self.not_resources:
            return not any(_resource_matches(p, resource) for p in self.not_resources)
        return False

    @classmethod
    def parse(cls, raw: Mapping[str, Any]) -> Statement:
        return cls(
            effect=str(raw.get("Effect", "Deny")),
            actions=_lower_all(_as_tuple(raw.get("Action"))),
            not_actions=_lower_all(_as_tuple(raw.get("NotAction"))),
            resources=_as_tuple(raw.get("Resource")),
            not_resources=_as_tuple(raw.get("NotResource")),
            conditions=raw.get("Condition") or {},
            principal=raw.get("Principal"),
            not_principal=raw.get("NotPrincipal"),
            sid=raw.get("Sid"),
        )


def _lower_all(patterns: tuple[str, ...]) -> tuple[str, ...]:
    return tuple(p.lower() for p in patterns)


@dataclass(frozen=True)
class PolicyDocument:
    statements: tuple[Statement, ...]

    @classmethod
    def parse(cls, document: Mapping[str, Any] | None) -> PolicyDocument:
        if not document:
            return cls(())
        raw = document.get("Statement", [])
        raw = [raw] if isinstance(raw, Mapping) else raw
        return cls(tuple(Statement.parse(s) for s in raw))


@dataclass(frozen=True)
class Access:
    """The outcome of asking whether a permission set allows an action."""

    allowed: bool
    on_any_resource: bool = False
    conditional: bool = False
    resources: tuple[str, ...] = ()

    @property
    def unconditional_on_any_resource(self) -> bool:
        return self.allowed and self.on_any_resource and not self.conditional


_DENIED = Access(False)


class PermissionSet:
    """The union of all statements that apply to one principal."""

    def __init__(self, statements: Iterable[Statement]) -> None:
        statements = list(statements)
        self.allow = [s for s in statements if s.is_allow]
        self.deny = [s for s in statements if not s.is_allow]

    def evaluate(self, action: str, resource: str = "*") -> Access:
        on_any = resource == "*"
        # An unconditional explicit Deny that matches always wins. A conditional Deny
        # might not apply, so it does not rule the access out for a "could this happen" check.
        for statement in self.deny:
            if statement.has_condition:
                continue
            matches = (
                statement.grants_on_any_resource()
                if on_any
                else statement.matches_resource(resource)
            )
            if matches and statement.matches_action(action):
                return _DENIED

        matched = [
            s
            for s in self.allow
            if s.matches_action(action)
            and (s.grants_on_any_resource() if on_any else s.matches_resource(resource))
        ]
        if not matched:
            return _DENIED
        return Access(
            allowed=True,
            on_any_resource=any(s.grants_on_any_resource() for s in matched),
            conditional=all(s.has_condition for s in matched),
            resources=tuple(sorted({r for s in matched for r in (s.resources or ("*",))})),
        )

    def allows(self, action: str, resource: str = "*") -> bool:
        return self.evaluate(action, resource).allowed

    def evaluate_action(self, action: str) -> Access:
        """Whether the action is allowed on *any* resource, and how broadly.

        Unlike :meth:`evaluate`, this does not require ``Resource:"*"`` — a grant
        scoped to a specific resource still counts, but comes back with
        ``on_any_resource=False`` so callers can lower their confidence. Used by
        escalation detection, where a scoped grant is a weaker but real signal.
        """
        for statement in self.deny:
            # Only a deny that blocks the action on every resource fully rules it out.
            if (
                not statement.has_condition
                and statement.grants_on_any_resource()
                and statement.matches_action(action)
            ):
                return _DENIED
        matched = [s for s in self.allow if s.matches_action(action)]
        if not matched:
            return _DENIED
        return Access(
            allowed=True,
            on_any_resource=any(s.grants_on_any_resource() for s in matched),
            conditional=all(s.has_condition for s in matched),
            resources=tuple(sorted({r for s in matched for r in (s.resources or ("*",))})),
        )

    def grants_admin(self) -> bool:
        """True if the principal has ``Action:"*"`` on ``Resource:"*"`` with no condition."""
        if self._explicitly_denied_everything():
            return False
        return any(
            not s.has_condition
            and s.grants_on_any_resource()
            and ("*" in s.actions or "*:*" in s.actions)
            for s in self.allow
        )

    def _explicitly_denied_everything(self) -> bool:
        return any(
            not d.has_condition
            and d.grants_on_any_resource()
            and ("*" in d.actions or "*:*" in d.actions)
            for d in self.deny
        )
