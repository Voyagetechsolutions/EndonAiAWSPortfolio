"""Privilege-escalation detection.

An IAM principal escalates privilege when it holds a permission that lets it grant
itself more permission. The techniques encoded here are the well-documented AWS IAM
escalation methods catalogued by Rhino Security Labs' research; each is expressed as
the permissions it requires.

Two things make this more than a permission checklist:

1. **Requirement logic.** A technique is a conjunction of clauses, each clause a set of
   interchangeable actions. `iam:PassRole` plus `lambda:CreateFunction` plus
   `lambda:InvokeFunction` is one path; missing any clause means the path is closed.
2. **The assume-role graph.** A principal that cannot escalate directly can still reach
   a role that can. Edges are built only where the caller is allowed `sts:AssumeRole`
   *and* the target role's trust policy admits the caller, then closed transitively.

Reference: Rhino Security Labs, "AWS IAM Privilege Escalation - Methods and Mitigation".
"""

from __future__ import annotations

from dataclasses import dataclass, field

from endon_core.findings import Severity
from endon_iam_analyzer.models import AccountSnapshot, Principal
from endon_iam_analyzer.policy import PermissionSet

Clause = tuple[str, ...]


@dataclass(frozen=True)
class Technique:
    id: str
    title: str
    severity: Severity
    clauses: tuple[Clause, ...]  # AND of clauses; each clause is an OR of action patterns
    remediation: str

    def satisfied_by(self, permissions: PermissionSet) -> TechniqueMatch | None:
        used: list[str] = []
        on_any = True
        conditional = False
        for clause in self.clauses:
            grant = self._first_grant(clause, permissions)
            if grant is None:
                return None
            action, access = grant
            used.append(action)
            on_any = on_any and access.on_any_resource
            conditional = conditional or access.conditional
        return TechniqueMatch(self, tuple(used), on_any_resource=on_any, conditional=conditional)

    @staticmethod
    def _first_grant(clause: Clause, permissions: PermissionSet):
        best = None
        for action in clause:
            access = permissions.evaluate_action(action)
            if not access.allowed:
                continue
            # Prefer an unconditional, any-resource grant when the clause offers a choice.
            if access.unconditional_on_any_resource:
                return action, access
            best = best or (action, access)
        return best


@dataclass(frozen=True)
class TechniqueMatch:
    technique: Technique
    actions_used: tuple[str, ...]
    on_any_resource: bool
    conditional: bool

    @property
    def confidence(self) -> str:
        return "high" if self.on_any_resource and not self.conditional else "conditional-or-scoped"

    @property
    def effective_severity(self) -> Severity:
        # A scoped or conditional grant is a weaker signal; drop it one level.
        if self.confidence == "high":
            return self.technique.severity
        order = list(Severity)
        return order[max(0, order.index(self.technique.severity) - 1)]


@dataclass
class ReachableEscalation:
    path: tuple[str, ...]  # principal -> role -> ... -> role that escalates
    matches: list[TechniqueMatch]


@dataclass
class EscalationResult:
    principal: Principal
    direct: list[TechniqueMatch] = field(default_factory=list)
    # role name -> the techniques reachable through it, with the assume path taken
    via_roles: dict[str, ReachableEscalation] = field(default_factory=dict)

    @property
    def can_escalate(self) -> bool:
        return bool(self.direct) or bool(self.via_roles)


# Direct self-service grants of administrator-equivalent power: CRITICAL.
_DIRECT_ADMIN = Severity.CRITICAL
# Escalation that depends on a passable privileged role or a compute service: HIGH.
_COMPUTE = Severity.HIGH

TECHNIQUES: tuple[Technique, ...] = (
    Technique(
        "CreateNewPolicyVersion",
        "Set a new default version on an attached managed policy",
        _DIRECT_ADMIN,
        (("iam:createpolicyversion",),),
        "Scope iam:CreatePolicyVersion to specific policy ARNs, or remove it.",
    ),
    Technique(
        "SetExistingDefaultPolicyVersion",
        "Roll a managed policy back to a more permissive version",
        _DIRECT_ADMIN,
        (("iam:setdefaultpolicyversion",),),
        "Scope iam:SetDefaultPolicyVersion to specific policy ARNs, or remove it.",
    ),
    Technique(
        "CreateAccessKey",
        "Create access keys for another IAM user",
        _DIRECT_ADMIN,
        (("iam:createaccesskey",),),
        "Restrict iam:CreateAccessKey to the caller's own user with a condition.",
    ),
    Technique(
        "CreateLoginProfile",
        "Set a console password on another IAM user",
        _DIRECT_ADMIN,
        (("iam:createloginprofile",),),
        "Restrict iam:CreateLoginProfile to the caller's own user.",
    ),
    Technique(
        "UpdateLoginProfile",
        "Reset another IAM user's console password",
        _DIRECT_ADMIN,
        (("iam:updateloginprofile",),),
        "Restrict iam:UpdateLoginProfile to the caller's own user.",
    ),
    Technique(
        "AttachUserPolicy",
        "Attach an administrator managed policy to a user",
        _DIRECT_ADMIN,
        (("iam:attachuserpolicy",),),
        "Remove iam:AttachUserPolicy or bound it with a PermissionsBoundary condition.",
    ),
    Technique(
        "AttachGroupPolicy",
        "Attach an administrator managed policy to the caller's group",
        _DIRECT_ADMIN,
        (("iam:attachgrouppolicy",),),
        "Remove iam:AttachGroupPolicy or scope it.",
    ),
    Technique(
        "AttachRolePolicy",
        "Attach an administrator managed policy to an assumable role",
        _DIRECT_ADMIN,
        (("iam:attachrolepolicy",),),
        "Remove iam:AttachRolePolicy or bound it with a PermissionsBoundary condition.",
    ),
    Technique(
        "PutUserPolicy",
        "Add an inline admin policy to a user",
        _DIRECT_ADMIN,
        (("iam:putuserpolicy",),),
        "Remove iam:PutUserPolicy or restrict it to the caller's own user.",
    ),
    Technique(
        "PutGroupPolicy",
        "Add an inline admin policy to the caller's group",
        _DIRECT_ADMIN,
        (("iam:putgrouppolicy",),),
        "Remove iam:PutGroupPolicy or scope it.",
    ),
    Technique(
        "PutRolePolicy",
        "Add an inline admin policy to an assumable role",
        _DIRECT_ADMIN,
        (("iam:putrolepolicy",),),
        "Remove iam:PutRolePolicy or scope it to specific roles.",
    ),
    Technique(
        "AddUserToGroup",
        "Add the caller to a more privileged group",
        _DIRECT_ADMIN,
        (("iam:addusertogroup",),),
        "Restrict iam:AddUserToGroup to specific group ARNs.",
    ),
    Technique(
        "UpdateAssumeRolePolicy",
        "Rewrite a privileged role's trust policy, then assume it",
        _DIRECT_ADMIN,
        (("iam:updateassumerolepolicy",), ("sts:assumerole",)),
        "Remove iam:UpdateAssumeRolePolicy or scope it to specific roles.",
    ),
    Technique(
        "PassRoleToLambda",
        "Pass a privileged role to a new Lambda function and invoke it",
        _COMPUTE,
        (
            ("iam:passrole",),
            ("lambda:createfunction",),
            ("lambda:invokefunction", "lambda:addpermission"),
        ),
        "Scope iam:PassRole to specific roles and constrain it with iam:PassedToService.",
    ),
    Technique(
        "PassRoleToEc2",
        "Launch an EC2 instance with a privileged instance profile",
        _COMPUTE,
        (("iam:passrole",), ("ec2:runinstances",)),
        "Scope iam:PassRole to specific roles; restrict ec2:RunInstances instance profiles.",
    ),
    Technique(
        "PassRoleToCloudFormation",
        "Deploy a CloudFormation stack with a privileged role",
        _COMPUTE,
        (("iam:passrole",), ("cloudformation:createstack",)),
        "Scope iam:PassRole to specific roles and restrict cloudformation:CreateStack.",
    ),
    Technique(
        "PassRoleToGlue",
        "Create a Glue development endpoint with a privileged role",
        _COMPUTE,
        (("iam:passrole",), ("glue:createdevendpoint", "glue:createjob")),
        "Scope iam:PassRole to specific roles and restrict Glue creation.",
    ),
    Technique(
        "PassRoleToSageMaker",
        "Create a SageMaker notebook with a privileged role",
        _COMPUTE,
        (("iam:passrole",), ("sagemaker:createnotebookinstance", "sagemaker:createtrainingjob")),
        "Scope iam:PassRole to specific roles and restrict SageMaker creation.",
    ),
    Technique(
        "UpdateLambdaCode",
        "Overwrite an existing Lambda function that already runs a privileged role",
        _COMPUTE,
        (("lambda:updatefunctioncode",),),
        "Restrict lambda:UpdateFunctionCode to specific function ARNs.",
    ),
)


def direct_matches(permissions: PermissionSet) -> list[TechniqueMatch]:
    # An account admin trivially satisfies every technique; report that as admin, not escalation.
    if permissions.grants_admin():
        return []
    return [m for t in TECHNIQUES if (m := t.satisfied_by(permissions)) is not None]


def _trust_admits(role: Principal, caller: Principal, account_id: str, partition: str) -> bool:
    """Whether ``role``'s trust policy lets ``caller`` assume it.

    Conservative: matches an explicit principal ARN, the caller's account root, or a
    wildcard principal. It does not resolve condition keys, so a trust that is open
    but condition-gated is treated as admitting the caller (worth surfacing).
    """
    if role.trust_policy is None:
        return False
    account_root = f"arn:{partition}:iam::{account_id}:root"
    for statement in role.trust_policy.statements:
        if not statement.is_allow or not statement.matches_action("sts:assumerole"):
            continue
        principals = _flatten_principal(statement.principal)
        for value in principals:
            if value == "*" or value == caller.arn or value == account_root:
                return True
            if value == account_id or value.endswith(f":{account_id}:root"):
                return True
    return False


def _flatten_principal(principal) -> list[str]:
    if principal is None:
        return []
    if isinstance(principal, str):
        return [principal]
    values: list[str] = []
    for entry in principal.values():
        values.extend(entry if isinstance(entry, list) else [entry])
    return values


def _assume_edges(snapshot: AccountSnapshot) -> dict[str, set[str]]:
    """principal name -> set of role names it can assume."""
    edges: dict[str, set[str]] = {}
    for principal in snapshot.principals():
        permissions = snapshot.permissions_for(principal)
        targets: set[str] = set()
        for role in snapshot.roles.values():
            if role.name == principal.name and role.kind == principal.kind:
                continue
            if not permissions.evaluate("sts:assumerole", role.arn).allowed:
                continue
            if _trust_admits(role, principal, snapshot.account_id, snapshot.partition):
                targets.add(role.name)
        if targets:
            edges[_key(principal)] = targets
    return edges


def _key(principal: Principal) -> str:
    return f"{principal.kind}:{principal.name}"


def analyze(snapshot: AccountSnapshot) -> dict[str, EscalationResult]:
    """Escalation results keyed by ``kind:name`` for every principal that can escalate."""
    direct_by_role: dict[str, list[TechniqueMatch]] = {}
    for role in snapshot.roles.values():
        matches = direct_matches(snapshot.permissions_for(role))
        if matches:
            direct_by_role[role.name] = matches

    edges = _assume_edges(snapshot)
    results: dict[str, EscalationResult] = {}
    for principal in snapshot.principals():
        result = EscalationResult(principal=principal)
        result.direct = direct_matches(snapshot.permissions_for(principal))
        for role_name, path in _reachable_roles(_key(principal), edges).items():
            if role_name in direct_by_role and role_name != principal.name:
                result.via_roles[role_name] = ReachableEscalation(path, direct_by_role[role_name])
        if result.can_escalate:
            results[_key(principal)] = result
    return results


def _reachable_roles(start: str, edges: dict[str, set[str]]) -> dict[str, tuple[str, ...]]:
    """Roles reachable from ``start`` via assume-role edges, with the shortest path to each."""
    reachable: dict[str, tuple[str, ...]] = {}
    frontier: list[tuple[str, tuple[str, ...]]] = [(start, (start,))]
    while frontier:
        node, path = frontier.pop(0)
        for role_name in sorted(edges.get(node, ())):
            role_key = f"role:{role_name}"
            if role_name in reachable or role_key == start:
                continue
            reachable[role_name] = path + (role_key,)
            frontier.append((role_key, path + (role_key,)))
    return reachable
