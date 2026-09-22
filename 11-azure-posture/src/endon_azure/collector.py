"""Pull live Azure resources via Azure Resource Graph (optional, live-only).

The scanner runs entirely on resource JSON, so this collector is the only part that touches
Azure — and it imports the Azure SDK lazily, so nothing here is needed to run the checks or the
tests. Install the extra to use it:

    pip install endon-azure[live]         # azure-identity + azure-mgmt-resourcegraph
    az login                              # or set env vars for a service principal

``collect`` runs one Resource Graph (KQL) query that returns every resource the checks care
about, already shaped like the JSON fixtures. This is exactly how a real CSPM tool inventories
a subscription — one query, not one API call per service.
"""

from __future__ import annotations

from typing import Any

# The resource types the checks evaluate — the query only pulls what we can assess.
_RESOURCE_TYPES = (
    "microsoft.storage/storageaccounts",
    "microsoft.network/networksecuritygroups",
    "microsoft.compute/disks",
    "microsoft.keyvault/vaults",
    "microsoft.security/pricings",
)

_QUERY = (
    "Resources | where tolower(type) in ({types}) "
    "| project id, name, type, location, resourceGroup, properties"
)


def collect(subscription_ids: list[str]) -> list[dict[str, Any]]:  # pragma: no cover - live only
    """Return Resource Graph rows for the given subscriptions (needs the [live] extra)."""
    from azure.identity import DefaultAzureCredential
    from azure.mgmt.resourcegraph import ResourceGraphClient
    from azure.mgmt.resourcegraph.models import QueryRequest

    client = ResourceGraphClient(DefaultAzureCredential())
    types = ", ".join(f'"{t}"' for t in _RESOURCE_TYPES)
    request = QueryRequest(subscriptions=subscription_ids, query=_QUERY.format(types=types))

    rows: list[dict[str, Any]] = []
    response = client.resources(request)
    rows.extend(response.data)
    while response.skip_token:
        request.options = {"skip_token": response.skip_token}
        response = client.resources(request)
        rows.extend(response.data)
    return rows
