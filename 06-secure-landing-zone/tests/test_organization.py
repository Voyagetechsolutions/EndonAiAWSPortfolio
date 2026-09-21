from endon_landingzone.organization import build_endon_organization
from endon_landingzone.scps import SCP_CATALOG


def test_org_structure_has_the_expected_ous_and_accounts():
    org = build_endon_organization()
    names = {ou.name for ou in org.root.walk()}
    assert {
        "Root",
        "Security",
        "LogArchive",
        "Workloads",
        "Production",
        "Development",
        "Sandbox",
    } <= names

    accounts = {a.name for a in org.root.all_accounts()}
    assert {"SecurityTooling", "LogArchive", "Production", "Development", "Sandbox"} <= accounts


def test_effective_scps_follow_the_path_to_root():
    org = build_endon_organization()
    production = {scp.id for scp in org.effective_scps("Production")}
    # Inherited from Root:
    assert {
        "region-allowlist",
        "deny-root-user",
        "prevent-leaving-organization",
        "protect-security-logging",
    } <= production
    # Attached to Workloads (Production's parent):
    assert {
        "protect-detection-services",
        "prevent-public-s3",
        "protect-endon-platform",
    } <= production


def test_sandbox_has_fewer_scps_than_production():
    org = build_endon_organization()
    sandbox = {scp.id for scp in org.effective_scps("Sandbox")}
    production = {scp.id for scp in org.effective_scps("Production")}
    assert "protect-detection-services" not in sandbox
    assert "prevent-public-s3" in sandbox  # sandbox still can't make data public
    assert production > sandbox


def test_every_scp_is_attached_somewhere_and_targets_real_ous():
    org = build_endon_organization()
    valid = {ou.name for ou in org.root.walk()}
    for scp in SCP_CATALOG:
        assert scp.targets, f"{scp.id} is attached to no OU"
        assert set(scp.targets) <= valid, f"{scp.id} targets an unknown OU"


def test_scp_documents_are_deny_based_and_well_formed():
    for scp in SCP_CATALOG:
        statements = scp.document["Statement"]
        assert statements
        for statement in statements:
            assert statement["Effect"] == "Deny"  # guardrails are deny-based over FullAWSAccess
            assert "Action" in statement or "NotAction" in statement
