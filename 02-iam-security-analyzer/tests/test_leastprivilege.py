from datetime import UTC, datetime

from endon_iam_analyzer.leastprivilege import ServiceUsage, build_least_privilege_policy
from endon_iam_analyzer.models import Principal

NOW = datetime(2026, 9, 15, tzinfo=UTC)
PRINCIPAL = Principal(kind="user", name="app", arn="arn:aws:iam::111122223333:user/app")


def test_policy_includes_only_recently_used_services():
    usage = [
        ServiceUsage("s3", "2026-09-10T00:00:00Z"),
        ServiceUsage("dynamodb", "2026-09-01T00:00:00Z"),
        ServiceUsage("ec2", "2025-01-01T00:00:00Z"),  # older than the window
        ServiceUsage("iam", None),  # never used
    ]

    policy = build_least_privilege_policy(PRINCIPAL, usage, within_days=90, now=NOW)

    actions = policy["Statement"][0]["Action"]
    assert actions == ["dynamodb:*", "s3:*"]
    assert "ec2:*" not in actions
    assert PRINCIPAL.arn in policy["_endon_note"]


def test_empty_usage_yields_an_empty_starting_point():
    policy = build_least_privilege_policy(PRINCIPAL, [], now=NOW)
    assert "empty policy" in policy["Statement"][0]["Action"][0]
