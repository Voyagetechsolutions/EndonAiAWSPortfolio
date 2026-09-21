"""The plain-text SOC board (CLI + evidence)."""

from endon_soc import cli, report


def test_console_board_shows_score_and_incidents(demo_service):
    text = report.render_console(demo_service)
    assert "SECURITY OPERATIONS CENTER" in text
    assert "Security Score" in text
    assert "Critical findings" in text
    assert "Recent incidents" in text
    # The three demo incidents' playbooks appear.
    assert "compromised-iam-user" in text
    assert "iam-risk-review" in text


def test_report_is_ascii_only(demo_service):
    text = report.render_console(demo_service)
    text.encode("ascii")  # raises if any non-ASCII slipped in (Windows console safe)


def test_cli_demo_prints_the_board(capsys):
    assert cli.main(["demo"]) == 0
    out = capsys.readouterr().out
    assert "SECURITY OPERATIONS CENTER" in out
    assert "/100" in out
