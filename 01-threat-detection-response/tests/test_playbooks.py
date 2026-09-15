import pytest

from endon_core.findings import Finding, Severity
from endon_detection.actions import REGISTRY
from endon_detection.playbooks import RULES, TRIAGE, select_playbook


def finding(finding_type, source="aws.guardduty", **tags):
    return Finding(
        source=source,
        type=finding_type,
        title=finding_type,
        severity=Severity.HIGH,
        account_id="123456789012",
        region="us-east-1",
        tags=tags,
    )


@pytest.mark.parametrize(
    ("finding_type", "playbook"),
    [
        ("UnauthorizedAccess:IAMUser/MaliciousIPCaller.Custom", "compromised-credentials"),
        ("CredentialAccess:IAMUser/AnomalousBehavior", "compromised-credentials"),
        ("Exfiltration:S3/AnomalousBehavior", "compromised-credentials"),
        (
            "UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS",
            "instance-credential-exfiltration",
        ),
        ("Stealth:IAMUser/CloudTrailLoggingDisabled", "logging-tampering"),
        ("CryptoCurrency:EC2/BitcoinTool.B!DNS", "compromised-ec2"),
        ("Backdoor:EC2/C&CActivity.B", "compromised-ec2"),
        ("Recon:EC2/Portscan", "compromised-ec2"),
        ("Execution:Runtime/NewBinaryExecuted", "compromised-ec2"),
        ("Recon:EC2/PortProbeUnprotectedPort", "exposed-ec2"),
        ("Policy:S3/BucketBlockPublicAccessDisabled", "s3-public-exposure"),
        ("Policy:S3/BucketAnonymousAccessGranted", "s3-public-exposure"),
        ("Policy:IAMUser/RootCredentialUsage", "root-account-activity"),
        ("Recon:IAMUser/MaliciousIPCaller.Custom", "triage"),
        ("Discovery:S3/AnomalousBehavior", "triage"),
    ],
)
def test_guardduty_finding_types(finding_type, playbook):
    assert select_playbook(finding(finding_type)).name == playbook


def test_brute_force_direction_decides_between_compromise_and_exposure():
    attacker = finding("UnauthorizedAccess:EC2/SSHBruteForce", resourceRole="ACTOR")
    victim = finding("UnauthorizedAccess:EC2/SSHBruteForce", resourceRole="TARGET")

    assert select_playbook(attacker).name == "compromised-ec2"
    assert select_playbook(victim).name == "exposed-ec2"


def test_endon_findings_never_select_principal_or_host_containment():
    forged = finding(
        "UnauthorizedAccess:IAMUser/MaliciousIPCaller.Custom", source="endon.posture-scanner"
    )
    assert select_playbook(forged) is TRIAGE


def test_endon_findings_route_to_their_own_playbooks():
    posture = finding("Posture:S3/BucketPubliclyAccessible", source="endon.posture-scanner")
    iam = finding("IAM:Role/PrivilegeEscalationPath", source="endon.iam-analyzer")

    assert select_playbook(posture).name == "s3-public-exposure"
    assert select_playbook(iam).name == "iam-risk-review"


def test_every_playbook_action_exists():
    playbooks = [rule.playbook for rule in RULES] + [TRIAGE]
    for playbook in playbooks:
        missing = [name for name in playbook.actions if name not in REGISTRY]
        assert not missing, f"{playbook.name} references unknown actions {missing}"
        assert playbook.actions[-1] == "notify", f"{playbook.name} must report its outcome last"
