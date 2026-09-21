"""The pipeline security gates, reusing Project 2 and Project 3 against an emulated account."""

import json

from endon_core.findings import Severity
from endon_pipeline import cli
from endon_pipeline.gate import iam_gate, posture_gate

REGION = "us-east-1"


def _admin_user(aws):
    iam = aws("iam")
    arn = iam.create_policy(
        PolicyName="AdminEquivalent",
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}],
            }
        ),
    )["Policy"]["Arn"]
    iam.create_user(UserName="ci-admin")
    iam.attach_user_policy(UserName="ci-admin", PolicyArn=arn)


def _public_bucket(aws):
    s3 = aws("s3")
    s3.create_bucket(Bucket="acme-public-data")
    s3.put_bucket_acl(Bucket="acme-public-data", ACL="public-read")


def test_iam_gate_fails_on_a_critical_finding(aws):
    _admin_user(aws)
    result = iam_gate(aws, REGION, fail_on=Severity.CRITICAL)
    assert not result.passed
    assert result.blocking >= 1
    assert result.name == "iam-analyzer"


def test_iam_gate_passes_on_a_clean_account(aws):
    result = iam_gate(aws, REGION, fail_on=Severity.CRITICAL)
    assert result.passed
    assert result.blocking == 0


def test_posture_gate_fails_on_a_public_bucket(aws):
    _public_bucket(aws)
    result = posture_gate(aws, REGION, fail_on=Severity.HIGH)
    assert not result.passed
    assert result.blocking >= 1


def test_cli_gate_exit_codes(aws, capsys):
    _admin_user(aws)
    assert cli.main(["gate", "--iam", "--region", REGION]) == 1  # blocking finding -> non-zero
    out = capsys.readouterr()
    assert json.loads(out.out)["gate"] == "iam-analyzer"
    assert "GATE FAILED" in out.err


def test_cli_simulate_prints_the_proof(capsys):
    assert cli.main(["simulate"]) == 0
    output = capsys.readouterr().out
    assert "GitHub OIDC trust" in output
    assert "BLAST RADIUS" in output
