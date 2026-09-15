from endon_posture.checks import CHECKS
from endon_posture.controls import CONTROLS


def test_control_ids_are_unique_and_typed():
    assert CONTROLS, "control catalog is empty"
    finding_types = [c.finding_type for c in CONTROLS.values()]
    assert len(finding_types) == len(set(finding_types)), "duplicate finding types"
    ids = list(CONTROLS.keys())
    assert len(ids) == len(set(ids)), "duplicate control ids"
    for control_id, control in CONTROLS.items():
        assert control.id == control_id
        assert control.finding_type.startswith(f"Posture:{control.service}/")
        assert control.remediation and control.rationale


def test_public_bucket_type_matches_the_project1_playbook():
    # Project 1's s3-public-exposure playbook routes exactly this type to auto-remediation.
    assert CONTROLS["S3-001"].finding_type == "Posture:S3/BucketPubliclyAccessible"


def test_every_service_has_at_least_one_check():
    check_services = {c.service for c in CHECKS}
    control_services = {c.service for c in CONTROLS.values()}
    assert control_services <= check_services
