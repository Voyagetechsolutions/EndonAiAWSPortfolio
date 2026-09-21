from endon_pipeline import report
from endon_pipeline.oidc import GitHubOidcConfig


def test_report_shows_both_proofs_and_all_pass():
    text = report.render_console(
        GitHubOidcConfig(owner="Voyagetechsolutions", repo="EndonAiAWSPortfolio")
    )
    assert "WHO CAN ASSUME THE DEPLOY ROLE" in text
    assert "BLAST RADIUS OF A COMPROMISED PIPELINE" in text
    assert "unauthorized assume attempts denied" in text
    assert "dangerous pipeline actions denied" in text
    # Every expectation held, so the warning line must be absent.
    assert "WARNING" not in text
