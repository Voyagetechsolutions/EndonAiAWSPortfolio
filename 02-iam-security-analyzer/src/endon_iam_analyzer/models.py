"""The IAM account model the analyzer reasons over.

An ``AccountSnapshot`` is a point-in-time picture of every principal, its policies and
its credential state. It is built once (from `iam:GetAccountAuthorizationDetails` plus
the credential report) and then queried repeatedly by the checks, so the analysis never
depends on live API calls and can run against a fixture in tests.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from typing import Any

from endon_core.findings import Resource
from endon_iam_analyzer.policy import PermissionSet, PolicyDocument, Statement

AWS_MANAGED_POLICY_MARKER = ":iam::aws:policy/"


@dataclass
class ManagedPolicy:
    arn: str
    name: str
    document: PolicyDocument
    attachment_count: int = 0

    @property
    def is_aws_managed(self) -> bool:
        return AWS_MANAGED_POLICY_MARKER in self.arn


@dataclass
class CredentialInfo:
    """One row of the IAM credential report, normalized."""

    user: str
    arn: str = ""
    password_enabled: bool = False
    mfa_active: bool = False
    access_key_1_active: bool = False
    access_key_1_last_rotated: str | None = None
    access_key_1_last_used: str | None = None
    access_key_2_active: bool = False
    access_key_2_last_rotated: str | None = None
    access_key_2_last_used: str | None = None

    @property
    def is_root(self) -> bool:
        return self.user == "<root_account>"

    @property
    def active_key_count(self) -> int:
        return int(self.access_key_1_active) + int(self.access_key_2_active)

    def active_keys(self) -> list[tuple[str, str | None, str | None]]:
        """Each active key as (slot, last_rotated, last_used)."""
        keys = []
        if self.access_key_1_active:
            keys.append(("1", self.access_key_1_last_rotated, self.access_key_1_last_used))
        if self.access_key_2_active:
            keys.append(("2", self.access_key_2_last_rotated, self.access_key_2_last_used))
        return keys


@dataclass
class Principal:
    kind: str  # "user" | "role" | "group"
    name: str
    arn: str
    path: str = "/"
    inline_policies: dict[str, PolicyDocument] = field(default_factory=dict)
    attached_policy_arns: list[str] = field(default_factory=list)
    group_names: list[str] = field(default_factory=list)  # users only
    trust_policy: PolicyDocument | None = None  # roles only
    tags: dict[str, str] = field(default_factory=dict)
    credentials: CredentialInfo | None = None

    @property
    def resource_type(self) -> str:
        return {"user": "AwsIamUser", "role": "AwsIamRole", "group": "AwsIamGroup"}[self.kind]

    def to_resource(self) -> Resource:
        return Resource(
            self.resource_type, self.arn, details={"name": self.name, "path": self.path}
        )

    @property
    def is_service_linked_role(self) -> bool:
        return self.kind == "role" and self.path.startswith(
            ("/aws-service-role/", "/aws-reserved/")
        )

    @property
    def is_protected(self) -> bool:
        """Break-glass principals are tagged so the analyzer can lower their severity."""
        return self.tags.get("endon:protected", "").strip().lower() in {"true", "yes", "1"}


@dataclass
class AccountSnapshot:
    account_id: str
    region: str = "us-east-1"
    partition: str = "aws"
    users: dict[str, Principal] = field(default_factory=dict)
    roles: dict[str, Principal] = field(default_factory=dict)
    groups: dict[str, Principal] = field(default_factory=dict)
    policies: dict[str, ManagedPolicy] = field(default_factory=dict)

    def principals(self) -> Iterable[Principal]:
        yield from self.users.values()
        yield from self.roles.values()
        yield from self.groups.values()

    def statements_for(self, principal: Principal) -> list[Statement]:
        """Every statement that applies to a principal, following group membership.

        Managed policies are resolved from the snapshot. An attached ARN the snapshot
        does not contain (an AWS managed policy IAM did not return) is skipped rather
        than guessed at.
        """
        statements: list[Statement] = []
        self._collect(principal, statements)
        if principal.kind == "user":
            for group_name in principal.group_names:
                group = self.groups.get(group_name)
                if group is not None:
                    self._collect(group, statements)
        return statements

    def _collect(self, principal: Principal, out: list[Statement]) -> None:
        for document in principal.inline_policies.values():
            out.extend(document.statements)
        for arn in principal.attached_policy_arns:
            policy = self.policies.get(arn)
            if policy is not None:
                out.extend(policy.document.statements)

    def permissions_for(self, principal: Principal) -> PermissionSet:
        return PermissionSet(self.statements_for(principal))

    def attached_customer_policies(self, principal: Principal) -> list[ManagedPolicy]:
        return [
            policy
            for arn in principal.attached_policy_arns
            if (policy := self.policies.get(arn)) is not None and not policy.is_aws_managed
        ]

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> AccountSnapshot:
        """Build a snapshot from a plain dict. Used by tests and fixtures.

        Shape mirrors what a hand-written scenario needs, not the AWS API::

            {
              "account_id": "111122223333",
              "policies": {"<arn>": {"name": "...", "document": {...}}},
              "users": [{"name": "...", "attached": ["<arn>"], "inline": {"n": {...}},
                         "groups": ["g"], "tags": {...}, "credentials": {...}}],
              "roles": [{"name": "...", "trust": {...}, "inline": {...}, "attached": [...]}],
              "groups": [{"name": "...", "attached": [...], "inline": {...}}],
            }
        """
        account_id = data["account_id"]
        partition = data.get("partition", "aws")
        snapshot = cls(
            account_id=account_id, region=data.get("region", "us-east-1"), partition=partition
        )

        for arn, policy in (data.get("policies") or {}).items():
            snapshot.policies[arn] = ManagedPolicy(
                arn=arn,
                name=policy.get("name", arn.rsplit("/", 1)[-1]),
                document=PolicyDocument.parse(policy["document"]),
                attachment_count=policy.get("attachment_count", 1),
            )

        for raw in data.get("users") or []:
            snapshot.users[raw["name"]] = _principal_from_dict("user", raw, account_id, partition)
        for raw in data.get("roles") or []:
            snapshot.roles[raw["name"]] = _principal_from_dict("role", raw, account_id, partition)
        for raw in data.get("groups") or []:
            snapshot.groups[raw["name"]] = _principal_from_dict("group", raw, account_id, partition)
        return snapshot


def _principal_from_dict(
    kind: str, raw: Mapping[str, Any], account_id: str, partition: str
) -> Principal:
    path = raw.get("path", "/")
    resource = {"user": "user", "role": "role", "group": "group"}[kind]
    arn = raw.get("arn") or f"arn:{partition}:iam::{account_id}:{resource}{path}{raw['name']}"
    credentials = raw.get("credentials")
    return Principal(
        kind=kind,
        name=raw["name"],
        arn=arn,
        path=path,
        inline_policies={n: PolicyDocument.parse(d) for n, d in (raw.get("inline") or {}).items()},
        attached_policy_arns=list(raw.get("attached") or []),
        group_names=list(raw.get("groups") or []),
        trust_policy=PolicyDocument.parse(raw["trust"]) if raw.get("trust") else None,
        tags=dict(raw.get("tags") or {}),
        credentials=CredentialInfo(user=raw["name"], **credentials) if credentials else None,
    )
