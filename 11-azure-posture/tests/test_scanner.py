"""The Azure benchmark and the checks."""

import json
from pathlib import Path

from endon_azure import checks, cli, controls
from endon_azure.resources import AzureResource
from endon_azure.scanner import scan
from endon_core.findings import Severity

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"


def test_every_control_fires_on_the_insecure_subscription(insecure):
    found = {f.control_id for f in scan(insecure)}
    expected = {c.id for c in controls.all_controls()}
    assert found == expected, f"controls that did not fire: {sorted(expected - found)}"


def test_the_secure_subscription_produces_no_findings(secure):
    assert scan(secure) == []


def test_findings_are_platform_findings_tagged_azure(insecure):
    sample = scan(insecure)[0]
    assert sample.source == "endon.azure"
    assert sample.type.startswith("AzurePosture:")
    assert sample.tags["cloud"] == "azure"
    assert sample.severity is Severity.CRITICAL  # public blob access sorts first
    assert sample.to_asff("arn:aws:securityhub:us-east-1:123456789012:product/x/y")["Id"]


def _res(rtype: str, **props) -> AzureResource:
    return AzureResource(
        id=f"/{rtype}/x",
        type=rtype.lower(),
        name="x",
        resource_group="rg",
        location="eastus",
        properties=props,
    )


def test_storage_checks():
    stg = "microsoft.storage/storageaccounts"
    assert checks._blob_public(_res(stg, allowBlobPublicAccess=True))
    assert not checks._blob_public(_res(stg, allowBlobPublicAccess=False))
    assert checks._http_allowed(_res(stg, supportsHttpsTrafficOnly=False))
    assert checks._open_network(_res(stg, networkAcls={"defaultAction": "Allow"}))
    assert not checks._open_network(_res(stg, networkAcls={"defaultAction": "Deny"}))


def test_nsg_admin_vs_other_port():
    nsg = "microsoft.network/networksecuritygroups"
    admin = _res(
        nsg,
        securityRules=[
            {
                "properties": {
                    "direction": "Inbound",
                    "access": "Allow",
                    "sourceAddressPrefix": "Internet",
                    "destinationPortRange": "3389",
                }
            }
        ],
    )
    other = _res(
        nsg,
        securityRules=[
            {
                "properties": {
                    "direction": "Inbound",
                    "access": "Allow",
                    "sourceAddressPrefix": "Internet",
                    "destinationPortRange": "9000",
                }
            }
        ],
    )
    internal = _res(
        nsg,
        securityRules=[
            {
                "properties": {
                    "direction": "Inbound",
                    "access": "Allow",
                    "sourceAddressPrefix": "10.0.0.0/8",
                    "destinationPortRange": "22",
                }
            }
        ],
    )
    assert checks._nsg_admin_open(admin)
    assert not checks._nsg_admin_open(other)
    assert checks._nsg_open_non_admin(other)
    assert not checks._nsg_admin_open(internal)


def test_disk_keyvault_defender():
    assert checks._disk_unencrypted(_res("microsoft.compute/disks"))
    assert not checks._disk_unencrypted(
        _res("microsoft.compute/disks", encryption={"type": "EncryptionAtRestWithPlatformKey"})
    )
    assert checks._no_purge_protection(_res("microsoft.keyvault/vaults"))
    assert not checks._no_purge_protection(
        _res("microsoft.keyvault/vaults", enablePurgeProtection=True)
    )
    assert checks._kv_public(_res("microsoft.keyvault/vaults", publicNetworkAccess="Enabled"))
    assert checks._defender_free(_res("microsoft.security/pricings", pricingTier="Free"))
    assert not checks._defender_free(_res("microsoft.security/pricings", pricingTier="Standard"))


def test_cli_gate(capsys):
    assert cli.main(["scan", str(FIXTURES / "insecure.json"), "--fail-on", "HIGH"]) == 1
    out = capsys.readouterr()
    assert "AZURE POSTURE SCAN" in out.out
    assert "GATE FAILED" in out.err

    assert cli.main(["scan", str(FIXTURES / "secure.json"), "--fail-on", "HIGH"]) == 0
    assert "PASSED" in capsys.readouterr().out


def test_cli_json(capsys):
    cli.main(["scan", str(FIXTURES / "insecure.json"), "--fail-on", "CRITICAL", "--json"])
    data = json.loads(capsys.readouterr().out)
    assert data["scanner"] == "endon-azure"
    assert data["by_severity"]["CRITICAL"] >= 1
