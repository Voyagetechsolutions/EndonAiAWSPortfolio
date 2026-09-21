"""GitHub OIDC trust: build the deploy role's trust policy and prove who can assume it.

When a GitHub Actions job runs, GitHub issues a short-lived OIDC token whose ``sub`` claim
encodes exactly where the job ran — ``repo:OWNER/REPO:ref:refs/heads/main`` for a push to
main, ``repo:OWNER/REPO:pull_request`` for a PR, and so on. AWS STS exchanges that token for
temporary credentials only if the role's trust policy accepts the claims. Get the
conditions right and a fork, a feature branch, a pull request, or an entirely different
repository simply cannot assume the role — there are no keys to steal because there are no
keys.

The simulator here evaluates a claim set against a trust policy, so "only main of our repo
can deploy" is a demonstrable fact.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from fnmatch import fnmatchcase
from typing import Any

OIDC_PROVIDER_DOMAIN = "token.actions.githubusercontent.com"
DEFAULT_AUDIENCE = "sts.amazonaws.com"


@dataclass(frozen=True)
class GitHubOidcConfig:
    owner: str
    repo: str
    allowed_branches: tuple[str, ...] = ("main",)
    allowed_environments: tuple[str, ...] = ()
    audience: str = DEFAULT_AUDIENCE

    @property
    def repository(self) -> str:
        return f"{self.owner}/{self.repo}"

    def allowed_subjects(self) -> list[str]:
        subs = [
            f"repo:{self.repository}:ref:refs/heads/{branch}" for branch in self.allowed_branches
        ]
        subs += [f"repo:{self.repository}:environment:{env}" for env in self.allowed_environments]
        return subs


@dataclass(frozen=True)
class GitHubClaims:
    """The claims GitHub Actions presents (from the job context)."""

    repository: str
    ref: str = "refs/heads/main"
    event_name: str = "push"
    environment: str | None = None
    actor: str = ""
    workflow: str = ""
    audience: str = DEFAULT_AUDIENCE

    @property
    def sub(self) -> str:
        # Mirrors GitHub's default subject claim.
        if self.environment:
            return f"repo:{self.repository}:environment:{self.environment}"
        if self.event_name == "pull_request":
            return f"repo:{self.repository}:pull_request"
        return f"repo:{self.repository}:ref:{self.ref}"

    def claim_context(self) -> dict[str, str]:
        return {
            f"{OIDC_PROVIDER_DOMAIN}:sub": self.sub,
            f"{OIDC_PROVIDER_DOMAIN}:aud": self.audience,
        }


def build_trust_policy(config: GitHubOidcConfig, account_id: str = "*") -> dict[str, Any]:
    provider_arn = f"arn:aws:iam::{account_id}:oidc-provider/{OIDC_PROVIDER_DOMAIN}"
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "GitHubActionsOidc",
                "Effect": "Allow",
                "Principal": {"Federated": provider_arn},
                "Action": "sts:AssumeRoleWithWebIdentity",
                "Condition": {
                    "StringEquals": {f"{OIDC_PROVIDER_DOMAIN}:aud": config.audience},
                    "StringLike": {f"{OIDC_PROVIDER_DOMAIN}:sub": config.allowed_subjects()},
                },
            }
        ],
    }


@dataclass(frozen=True)
class TrustDecision:
    allowed: bool
    reason: str


@dataclass
class OidcTrustSimulator:
    trust_policy: dict[str, Any]
    _statements: list[dict] = field(default_factory=list)

    def __post_init__(self) -> None:
        self._statements = self.trust_policy.get("Statement", [])

    def evaluate(self, claims: GitHubClaims) -> TrustDecision:
        context = claims.claim_context()
        for statement in self._statements:
            if statement.get("Effect") != "Allow":
                continue
            if "sts:AssumeRoleWithWebIdentity" not in _as_list(statement.get("Action", [])):
                continue
            missing = self._unmet_condition(statement.get("Condition", {}), context)
            if missing is None:
                return TrustDecision(True, f"claims accepted (sub={claims.sub})")
            return TrustDecision(False, missing)
        return TrustDecision(False, "no web-identity statement matched")

    def can_assume(self, claims: GitHubClaims) -> bool:
        return self.evaluate(claims).allowed

    @staticmethod
    def _unmet_condition(condition: dict, context: dict[str, str]) -> str | None:
        for operator, mapping in condition.items():
            for key, expected in mapping.items():
                actual = context.get(key)
                patterns = _as_list(expected)
                if operator == "StringEquals":
                    ok = actual in patterns
                elif operator == "StringLike":
                    ok = actual is not None and any(fnmatchcase(actual, p) for p in patterns)
                else:
                    raise ValueError(f"Unsupported trust condition operator: {operator}")
                if not ok:
                    return f"{key}={actual!r} fails {operator} {patterns}"
        return None


def _as_list(value) -> list:
    if value is None:
        return []
    return value if isinstance(value, list) else [value]
