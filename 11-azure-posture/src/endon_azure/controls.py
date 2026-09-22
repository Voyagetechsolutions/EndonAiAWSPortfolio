"""The Azure CSPM control catalog.

Finding types follow ``AzurePosture:<Service>/<Name>`` — the Azure sibling of Project 3's
``Posture:<Service>/<Name>`` — so an Azure finding rides the same bus, stores, SOC and ASFF as
an AWS one. Same platform, second cloud.
"""

from __future__ import annotations

from dataclasses import dataclass

from endon_core.findings import Domain, Severity


@dataclass(frozen=True)
class Control:
    id: str
    service: str
    resource_type: str  # the Azure resource type this control applies to (lower-cased)
    title: str
    severity: Severity
    finding_type: str
    domain: Domain
    remediation: str


def _c(cid, service, rtype, name, title, severity, domain, remediation) -> Control:
    return Control(
        cid, service, rtype, title, severity, f"AzurePosture:{service}/{name}", domain, remediation
    )


_ALL = [
    _c(
        "AZ-STG-001",
        "Storage",
        "microsoft.storage/storageaccounts",
        "BlobPublicAccess",
        "Storage account allows public blob access",
        Severity.CRITICAL,
        Domain.DATA_PROTECTION,
        "Set allowBlobPublicAccess = false on the storage account.",
    ),
    _c(
        "AZ-STG-002",
        "Storage",
        "microsoft.storage/storageaccounts",
        "HttpAllowed",
        "Storage account allows unencrypted HTTP",
        Severity.HIGH,
        Domain.DATA_PROTECTION,
        "Set supportsHttpsTrafficOnly = true.",
    ),
    _c(
        "AZ-STG-003",
        "Storage",
        "microsoft.storage/storageaccounts",
        "OpenNetworkAccess",
        "Storage account is reachable from all networks",
        Severity.MEDIUM,
        Domain.INFRASTRUCTURE,
        "Set networkAcls.defaultAction = Deny and allow only known VNets/IPs.",
    ),
    _c(
        "AZ-NSG-001",
        "Network",
        "microsoft.network/networksecuritygroups",
        "AdminPortFromInternet",
        "NSG allows SSH/RDP inbound from the Internet",
        Severity.HIGH,
        Domain.INFRASTRUCTURE,
        "Remove Internet-sourced inbound rules on 22/3389; use a bastion or JIT access.",
    ),
    _c(
        "AZ-NSG-002",
        "Network",
        "microsoft.network/networksecuritygroups",
        "OpenIngress",
        "NSG allows inbound from the Internet",
        Severity.MEDIUM,
        Domain.INFRASTRUCTURE,
        "Scope inbound rules to known source prefixes.",
    ),
    _c(
        "AZ-DISK-001",
        "Compute",
        "microsoft.compute/disks",
        "DiskNotEncrypted",
        "Managed disk is not encrypted",
        Severity.HIGH,
        Domain.DATA_PROTECTION,
        "Enable encryption at rest (platform-managed or customer-managed key).",
    ),
    _c(
        "AZ-KV-001",
        "KeyVault",
        "microsoft.keyvault/vaults",
        "NoPurgeProtection",
        "Key Vault does not have purge protection",
        Severity.HIGH,
        Domain.DATA_PROTECTION,
        "Enable enablePurgeProtection so keys/secrets cannot be permanently deleted early.",
    ),
    _c(
        "AZ-KV-002",
        "KeyVault",
        "microsoft.keyvault/vaults",
        "PublicNetworkAccess",
        "Key Vault is reachable from public networks",
        Severity.MEDIUM,
        Domain.DATA_PROTECTION,
        "Set publicNetworkAccess = Disabled and use private endpoints.",
    ),
    _c(
        "AZ-DEF-001",
        "Defender",
        "microsoft.security/pricings",
        "DefenderPlanFree",
        "Microsoft Defender for Cloud plan is not enabled",
        Severity.MEDIUM,
        Domain.DETECTION,
        "Set the Defender pricing tier to Standard for this resource type.",
    ),
]

BY_ID: dict[str, Control] = {c.id: c for c in _ALL}


def all_controls() -> list[Control]:
    return list(_ALL)


def get(control_id: str) -> Control:
    return BY_ID[control_id]
