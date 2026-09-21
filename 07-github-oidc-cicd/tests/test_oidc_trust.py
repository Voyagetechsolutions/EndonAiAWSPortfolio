"""The OIDC trust proof: exactly who can (and cannot) assume the deploy role."""

import pytest

from endon_pipeline.oidc import (
    GitHubClaims,
    GitHubOidcConfig,
    OidcTrustSimulator,
    build_trust_policy,
)

CONFIG = GitHubOidcConfig(owner="mthokozisi-chaza", repo="endon-ai", allowed_branches=("main",))
REPO = CONFIG.repository


@pytest.fixture
def simulator():
    return OidcTrustSimulator(build_trust_policy(CONFIG, account_id="123456789012"))


def test_push_to_main_of_the_exact_repo_is_allowed(simulator):
    decision = simulator.evaluate(
        GitHubClaims(repository=REPO, ref="refs/heads/main", event_name="push")
    )
    assert decision.allowed


@pytest.mark.parametrize(
    "claims",
    [
        GitHubClaims(repository=REPO, ref="refs/heads/feature-x"),  # a different branch
        GitHubClaims(repository="attacker/endon-ai", ref="refs/heads/main"),  # a fork / other owner
        GitHubClaims(
            repository="mthokozisi-chaza/other-repo", ref="refs/heads/main"
        ),  # a different repo
        GitHubClaims(repository=REPO, event_name="pull_request"),  # a pull request
        GitHubClaims(repository=REPO, ref="refs/tags/v1.0"),  # a tag
    ],
)
def test_everything_other_than_main_is_denied(simulator, claims):
    assert not simulator.can_assume(claims)


def test_wrong_audience_is_denied(simulator):
    # A token minted for a different audience must not be accepted (token confusion).
    decision = simulator.evaluate(
        GitHubClaims(repository=REPO, ref="refs/heads/main", audience="https://github.com/attacker")
    )
    assert not decision.allowed
    assert "aud" in decision.reason


def test_environment_deployments_can_be_allowed_explicitly():
    config = GitHubOidcConfig(
        owner="mthokozisi-chaza", repo="endon-ai", allowed_environments=("production",)
    )
    simulator = OidcTrustSimulator(build_trust_policy(config))
    allowed = simulator.can_assume(
        GitHubClaims(repository=config.repository, environment="production")
    )
    other_env = simulator.can_assume(
        GitHubClaims(repository=config.repository, environment="staging")
    )
    assert allowed
    assert not other_env


def test_trust_policy_uses_web_identity_and_pins_audience():
    policy = build_trust_policy(CONFIG, account_id="123456789012")
    statement = policy["Statement"][0]
    assert statement["Action"] == "sts:AssumeRoleWithWebIdentity"
    assert statement["Principal"]["Federated"].endswith(
        ":oidc-provider/token.actions.githubusercontent.com"
    )
    assert (
        statement["Condition"]["StringEquals"]["token.actions.githubusercontent.com:aud"]
        == "sts.amazonaws.com"
    )
