"""Detection for each Azure control: a predicate over a resource's properties."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from endon_azure.resources import AzureResource

_INTERNET_SOURCES = {"internet", "*", "0.0.0.0/0", "any"}
_ADMIN_PORTS = (22, 3389)


@dataclass(frozen=True)
class Check:
    control_id: str
    predicate: Callable[[AzureResource], bool]


# ---- Storage ----------------------------------------------------------------------
def _blob_public(r: AzureResource) -> bool:
    return r.prop("allowBlobPublicAccess") is True


def _http_allowed(r: AzureResource) -> bool:
    return r.prop("supportsHttpsTrafficOnly") is False


def _open_network(r: AzureResource) -> bool:
    return str(r.prop("networkAcls.defaultAction", "Allow")).lower() == "allow"


# ---- Network security groups ------------------------------------------------------
def _security_rules(r: AzureResource) -> list[dict]:
    return r.prop("securityRules", []) or []


def _inbound_from_internet(rule: dict) -> bool:
    props = rule.get("properties", rule)
    if str(props.get("direction", "")).lower() != "inbound":
        return False
    if str(props.get("access", "")).lower() != "allow":
        return False
    sources = props.get("sourceAddressPrefixes") or [props.get("sourceAddressPrefix", "")]
    return any(str(s).lower() in _INTERNET_SOURCES for s in sources)


def _ports(rule: dict) -> list[str]:
    props = rule.get("properties", rule)
    return props.get("destinationPortRanges") or [props.get("destinationPortRange", "")]


def _covers_admin_port(port_range: str) -> bool:
    port_range = str(port_range)
    if port_range in ("*", "0-65535"):
        return True
    if "-" in port_range:
        lo, hi = (int(p) for p in port_range.split("-", 1))
        return any(lo <= p <= hi for p in _ADMIN_PORTS)
    return port_range.isdigit() and int(port_range) in _ADMIN_PORTS


def _nsg_admin_open(r: AzureResource) -> bool:
    return any(
        _inbound_from_internet(rule) and any(_covers_admin_port(p) for p in _ports(rule))
        for rule in _security_rules(r)
    )


def _nsg_open_non_admin(r: AzureResource) -> bool:
    return any(
        _inbound_from_internet(rule) and not any(_covers_admin_port(p) for p in _ports(rule))
        for rule in _security_rules(r)
    )


# ---- Disks / Key Vault / Defender -------------------------------------------------
def _disk_unencrypted(r: AzureResource) -> bool:
    encryption = r.prop("encryption")
    settings = r.prop("encryptionSettingsCollection")
    if isinstance(encryption, dict) and encryption.get("type"):
        return False
    return not (isinstance(settings, dict) and settings.get("enabled") is True)


def _no_purge_protection(r: AzureResource) -> bool:
    return r.prop("enablePurgeProtection") is not True


def _kv_public(r: AzureResource) -> bool:
    return str(r.prop("publicNetworkAccess", "Enabled")).lower() == "enabled"


def _defender_free(r: AzureResource) -> bool:
    return str(r.prop("pricingTier", "Free")).lower() != "standard"


CHECKS: dict[str, tuple[Check, ...]] = {
    "microsoft.storage/storageaccounts": (
        Check("AZ-STG-001", _blob_public),
        Check("AZ-STG-002", _http_allowed),
        Check("AZ-STG-003", _open_network),
    ),
    "microsoft.network/networksecuritygroups": (
        Check("AZ-NSG-001", _nsg_admin_open),
        Check("AZ-NSG-002", _nsg_open_non_admin),
    ),
    "microsoft.compute/disks": (Check("AZ-DISK-001", _disk_unencrypted),),
    "microsoft.keyvault/vaults": (
        Check("AZ-KV-001", _no_purge_protection),
        Check("AZ-KV-002", _kv_public),
    ),
    "microsoft.security/pricings": (Check("AZ-DEF-001", _defender_free),),
}
