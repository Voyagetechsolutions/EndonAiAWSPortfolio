"""The plan parser and the CLI gate."""

import json
from pathlib import Path

from endon_tfscan import cli
from endon_tfscan.plan import Plan

PLANS = Path(__file__).resolve().parents[1] / "terraform" / "plans"


def test_parser_reads_resource_config(insecure_plan):
    ebs = insecure_plan.of_type("aws_ebs_volume")
    assert ebs and ebs[0].get("encrypted") is False
    sg = insecure_plan.of_type("aws_security_group")[0]
    assert sg.blocks("ingress")[0]["from_port"] == 22


def test_parser_skips_destroys_and_data_sources():
    doc = {
        "resource_changes": [
            {
                "address": "aws_s3_bucket.gone",
                "mode": "managed",
                "type": "aws_s3_bucket",
                "name": "gone",
                "provider_name": "registry.terraform.io/hashicorp/aws",
                "change": {"actions": ["delete"], "after": None},
            },
            {
                "address": "data.aws_ami.ubuntu",
                "mode": "data",
                "type": "aws_ami",
                "name": "ubuntu",
                "provider_name": "registry.terraform.io/hashicorp/aws",
                "change": {"actions": ["read"], "after": {"id": "ami-1"}},
            },
        ]
    }
    assert Plan.from_json(doc).resources == ()


def test_cli_fails_the_gate_on_insecure_plan(capsys):
    code = cli.main(["scan", str(PLANS / "insecure.plan.json"), "--fail-on", "HIGH"])
    assert code == 1
    captured = capsys.readouterr()
    assert "GATE FAILED" in captured.err
    assert "TERRAFORM IaC SECURITY SCAN" in captured.out


def test_cli_passes_the_gate_on_secure_plan(capsys):
    code = cli.main(["scan", str(PLANS / "secure.plan.json"), "--fail-on", "HIGH"])
    assert code == 0
    assert "PASSED" in capsys.readouterr().out


def test_cli_json_output(capsys):
    code = cli.main(["scan", str(PLANS / "insecure.plan.json"), "--fail-on", "CRITICAL", "--json"])
    assert code == 1
    data = json.loads(capsys.readouterr().out)
    assert data["scanner"] == "endon-tfscan"
    assert data["total"] >= 13
    assert data["by_severity"]["CRITICAL"] >= 1


def test_cli_fail_on_low_blocks_everything(capsys):
    # With fail-on LOW even a MEDIUM finding blocks; the insecure plan has several.
    assert cli.main(["scan", str(PLANS / "insecure.plan.json"), "--fail-on", "LOW"]) == 1
