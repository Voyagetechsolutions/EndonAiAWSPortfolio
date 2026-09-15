import pytest

from endon_iam_analyzer.policy import PermissionSet, PolicyDocument


def perms(*statements) -> PermissionSet:
    return PermissionSet(PolicyDocument.parse({"Statement": list(statements)}).statements)


def allow(action, resource="*", **extra):
    return {"Effect": "Allow", "Action": action, "Resource": resource, **extra}


def deny(action, resource="*", **extra):
    return {"Effect": "Deny", "Action": action, "Resource": resource, **extra}


@pytest.mark.parametrize(
    ("statement_action", "query", "expected"),
    [
        ("s3:GetObject", "s3:GetObject", True),
        ("s3:GetObject", "s3:getobject", True),  # IAM actions are case-insensitive
        ("s3:Get*", "s3:GetObject", True),
        ("s3:*", "s3:GetObject", True),
        ("*", "iam:PassRole", True),
        ("s3:Get*", "s3:PutObject", False),
        ("ec2:*", "s3:GetObject", False),
    ],
)
def test_action_matching(statement_action, query, expected):
    assert perms(allow(statement_action)).allows(query) is expected


def test_explicit_deny_overrides_allow():
    permissions = perms(allow("*"), deny("s3:DeleteObject"))
    assert permissions.allows("s3:GetObject")
    assert not permissions.allows("s3:DeleteObject")


def test_conditional_deny_does_not_block_potential_access():
    permissions = perms(
        allow("s3:*"),
        deny("s3:DeleteObject", Condition={"Bool": {"aws:MultiFactorAuthPresent": "false"}}),
    )
    # A conditional deny might not apply, so the action is still potentially allowed.
    assert permissions.allows("s3:DeleteObject")


def test_resource_scoping():
    permissions = perms(allow("s3:GetObject", resource="arn:aws:s3:::reports/*"))
    assert permissions.evaluate("s3:GetObject", "arn:aws:s3:::reports/q3.csv").allowed
    assert not permissions.evaluate("s3:GetObject", "arn:aws:s3:::secrets/key").allowed
    assert not permissions.evaluate("s3:GetObject").on_any_resource  # query "*" needs Resource "*"


def test_conditional_grant_is_flagged():
    access = perms(
        allow(
            "iam:PassRole",
            Condition={"StringEquals": {"iam:PassedToService": "lambda.amazonaws.com"}},
        )
    ).evaluate("iam:PassRole")
    assert access.allowed
    assert access.conditional
    assert not access.unconditional_on_any_resource


def test_grants_admin():
    assert perms(allow("*")).grants_admin()
    assert perms(allow("*:*")).grants_admin()
    assert not perms(allow("s3:*")).grants_admin()
    assert not perms(allow("*", resource="arn:aws:s3:::b")).grants_admin()
    assert not perms(allow("*"), deny("*")).grants_admin()


def test_admin_via_conditional_wildcard_is_not_counted():
    conditional_admin = perms(allow("*", Condition={"IpAddress": {"aws:SourceIp": "10.0.0.0/8"}}))
    assert not conditional_admin.grants_admin()


def test_notaction_allow_is_not_admin_but_grants_broadly():
    permissions = perms({"Effect": "Allow", "NotAction": "iam:*", "Resource": "*"})
    assert not permissions.grants_admin()
    assert permissions.allows("s3:DeleteObject")
    assert not permissions.allows("iam:CreateUser")


def test_statement_list_and_single_forms_parse_equally():
    single = PolicyDocument.parse(
        {"Statement": {"Effect": "Allow", "Action": "s3:*", "Resource": "*"}}
    )
    listed = PolicyDocument.parse(
        {"Statement": [{"Effect": "Allow", "Action": "s3:*", "Resource": "*"}]}
    )
    assert len(single.statements) == len(listed.statements) == 1
