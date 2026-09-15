import json

from detection_testkit import ACCOUNT_ID, REGION, instance_resource
from endon_core.events import DetailType
from endon_core.incidents import ActionStatus, IncidentStatus
from endon_detection import samples
from endon_detection.actions.iam import QUARANTINE_POLICY_NAME, REVOKE_SESSIONS_POLICY_NAME
from endon_detection.guardrails import Guardrails

EC2_TRUST = json.dumps(
    {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "ec2.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
)


def key_statuses(aws, user):
    return {
        k["AccessKeyId"]: k["Status"]
        for k in aws("iam").list_access_keys(UserName=user)["AccessKeyMetadata"]
    }


def test_compromised_user_is_contained(aws, engine, iam_user):
    event = samples.api_calls_from_malicious_ip(
        ACCOUNT_ID, REGION, iam_user["name"], iam_user["keys"][0]
    )

    [incident] = engine.handle_event(event)

    assert incident.playbook == "compromised-credentials"
    assert incident.status is IncidentStatus.CONTAINED
    assert incident.contained_at is not None

    iam = aws("iam")
    # Every key is disabled, including the second key the finding never mentioned.
    assert set(key_statuses(aws, iam_user["name"]).values()) == {"Inactive"}
    policy = iam.get_user_policy(UserName=iam_user["name"], PolicyName=QUARANTINE_POLICY_NAME)[
        "PolicyDocument"
    ]
    assert policy["Statement"][0] == {
        "Sid": "EndonIncidentQuarantine",
        "Effect": "Deny",
        "Action": "*",
        "Resource": "*",
    }
    tags = {t["Key"]: t["Value"] for t in iam.list_user_tags(UserName=iam_user["name"])["Tags"]}
    assert tags["endon:incident-id"] == incident.incident_id
    assert tags["endon:incident-status"] == "QUARANTINED"

    disable = next(a for a in incident.actions if a.action == "disable_access_keys")
    assert sorted(disable.data["deactivatedAccessKeyIds"]) == sorted(iam_user["keys"])


def test_protected_user_is_left_for_humans(aws, engine, iam_user):
    aws("iam").tag_user(
        UserName=iam_user["name"], Tags=[{"Key": "endon:protected", "Value": "true"}]
    )
    event = samples.api_calls_from_malicious_ip(
        ACCOUNT_ID, REGION, iam_user["name"], iam_user["keys"][0]
    )

    [incident] = engine.handle_event(event)

    assert incident.status is IncidentStatus.SUPPRESSED
    assert set(key_statuses(aws, iam_user["name"]).values()) == {"Active"}
    assert aws("iam").list_user_policies(UserName=iam_user["name"])["PolicyNames"] == []


def test_stolen_instance_role_sessions_are_revoked(aws, engine, bus, ec2_instance):
    aws("iam").create_role(RoleName="web-app-role", AssumeRolePolicyDocument=EC2_TRUST)
    event = samples.instance_credential_exfiltration(
        ACCOUNT_ID, REGION, "web-app-role", instance_resource(ec2_instance)
    )

    [incident] = engine.handle_event(event)

    assert incident.playbook == "instance-credential-exfiltration"
    assert incident.status is IncidentStatus.CONTAINED
    policy = aws("iam").get_role_policy(
        RoleName="web-app-role", PolicyName=REVOKE_SESSIONS_POLICY_NAME
    )
    statement = policy["PolicyDocument"]["Statement"][0]
    assert statement["Effect"] == "Deny"
    assert "aws:TokenIssueTime" in statement["Condition"]["DateLessThan"]

    [request] = bus.events(DetailType.FORENSICS_REQUESTED)
    assert request["detail"]["instanceId"] == ec2_instance["instance_id"]
    assert request["detail"]["incidentId"] == incident.incident_id


def test_responder_never_revokes_its_own_role(aws, make_engine, ec2_instance):
    aws("iam").create_role(RoleName="endon-responder", AssumeRolePolicyDocument=EC2_TRUST)
    engine = make_engine(
        guardrails=Guardrails(aws, responder_role_names=frozenset({"endon-responder"}))
    )
    event = samples.instance_credential_exfiltration(
        ACCOUNT_ID, REGION, "endon-responder", instance_resource(ec2_instance)
    )

    [incident] = engine.handle_event(event)

    assert incident.status is IncidentStatus.SUPPRESSED
    revoke = next(a for a in incident.actions if a.action == "revoke_role_sessions")
    assert revoke.status is ActionStatus.SUPPRESSED
    assert "own role" in revoke.message
    assert aws("iam").list_role_policies(RoleName="endon-responder")["PolicyNames"] == []


def test_service_linked_roles_are_never_modified(aws, engine, ec2_instance):
    aws("iam").create_role(
        RoleName="AWSServiceRoleForAutoScaling",
        Path="/aws-service-role/autoscaling.amazonaws.com/",
        AssumeRolePolicyDocument=EC2_TRUST,
    )
    event = samples.instance_credential_exfiltration(
        ACCOUNT_ID, REGION, "AWSServiceRoleForAutoScaling", instance_resource(ec2_instance)
    )

    [incident] = engine.handle_event(event)

    assert incident.status is IncidentStatus.SUPPRESSED
    assert (
        aws("iam").list_role_policies(RoleName="AWSServiceRoleForAutoScaling")["PolicyNames"] == []
    )
