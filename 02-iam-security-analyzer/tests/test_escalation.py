from endon_iam_analyzer import escalation
from endon_iam_analyzer.models import AccountSnapshot
from endon_iam_analyzer.policy import PermissionSet, PolicyDocument


def perms(*statements) -> PermissionSet:
    return PermissionSet(PolicyDocument.parse({"Statement": list(statements)}).statements)


def allow(action, resource="*", **extra):
    return {"Effect": "Allow", "Action": action, "Resource": resource, **extra}


def technique_ids(matches):
    return {m.technique.id for m in matches}


def test_direct_attach_user_policy_is_detected():
    matches = escalation.direct_matches(perms(allow("iam:AttachUserPolicy")))
    assert "AttachUserPolicy" in technique_ids(matches)


def test_passrole_requires_every_clause():
    passrole_only = escalation.direct_matches(perms(allow("iam:PassRole")))
    assert "PassRoleToLambda" not in technique_ids(passrole_only)

    full = escalation.direct_matches(
        perms(allow(["iam:PassRole", "lambda:CreateFunction", "lambda:InvokeFunction"]))
    )
    assert "PassRoleToLambda" in technique_ids(full)


def test_account_admin_is_reported_as_admin_not_escalation():
    assert escalation.direct_matches(perms(allow("*"))) == []


def test_scoped_grant_lowers_confidence_and_severity():
    scoped = escalation.direct_matches(
        perms(allow("iam:AttachUserPolicy", resource="arn:aws:iam::111122223333:user/self"))
    )
    match = next(m for m in scoped if m.technique.id == "AttachUserPolicy")
    assert match.confidence == "conditional-or-scoped"
    assert match.effective_severity.rank < match.technique.severity.rank


def test_transitive_escalation_through_assumable_role():
    snapshot = AccountSnapshot.from_dict(
        {
            "account_id": "111122223333",
            "policies": {
                "arn:aws:iam::111122223333:policy/assume": {
                    "name": "assume",
                    "document": {
                        "Statement": [
                            allow(
                                "sts:AssumeRole",
                                resource="arn:aws:iam::111122223333:role/escalator",
                            )
                        ]
                    },
                },
                "arn:aws:iam::111122223333:policy/attach": {
                    "name": "attach",
                    "document": {"Statement": [allow("iam:PutUserPolicy")]},
                },
            },
            "users": [{"name": "mallory", "attached": ["arn:aws:iam::111122223333:policy/assume"]}],
            "roles": [
                {
                    "name": "escalator",
                    "attached": ["arn:aws:iam::111122223333:policy/attach"],
                    "trust": {
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Principal": {"AWS": "arn:aws:iam::111122223333:user/mallory"},
                                "Action": "sts:AssumeRole",
                            }
                        ]
                    },
                }
            ],
        }
    )

    results = escalation.analyze(snapshot)

    mallory = results["user:mallory"]
    assert not mallory.direct
    assert "escalator" in mallory.via_roles
    assert mallory.via_roles["escalator"].path == ("user:mallory", "role:escalator")


def test_no_edge_when_trust_policy_excludes_the_caller():
    snapshot = AccountSnapshot.from_dict(
        {
            "account_id": "111122223333",
            "policies": {
                "arn:aws:iam::111122223333:policy/assume": {
                    "name": "assume",
                    "document": {"Statement": [allow("sts:AssumeRole")]},
                },
                "arn:aws:iam::111122223333:policy/attach": {
                    "name": "attach",
                    "document": {"Statement": [allow("iam:PutUserPolicy")]},
                },
            },
            "users": [{"name": "mallory", "attached": ["arn:aws:iam::111122223333:policy/assume"]}],
            "roles": [
                {
                    "name": "escalator",
                    "attached": ["arn:aws:iam::111122223333:policy/attach"],
                    # Trusts only a different, specific user.
                    "trust": {
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Principal": {"AWS": "arn:aws:iam::111122223333:user/someone-else"},
                                "Action": "sts:AssumeRole",
                            }
                        ]
                    },
                }
            ],
        }
    )

    results = escalation.analyze(snapshot)
    assert "user:mallory" not in results  # cannot actually assume the escalating role
