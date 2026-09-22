"""Normalize Azure resources into one shape the checks evaluate.

The input is what Azure Resource Graph (or ``az resource list -o json``) returns: a list of
rows, each with an ``id``, a ``type`` like ``microsoft.storage/storageAccounts``, a location,
a resource group and a ``properties`` object holding the real configuration. This keeps the
checks agnostic to how the data was fetched — live via the Azure SDK (``collector.py``) or a
committed JSON export in the tests.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class AzureResource:
    id: str
    type: str  # lower-cased, e.g. "microsoft.storage/storageaccounts"
    name: str
    resource_group: str
    location: str
    properties: dict[str, Any]

    def prop(self, path: str, default: Any = None) -> Any:
        """Dotted lookup into properties, e.g. ``networkAcls.defaultAction``."""
        node: Any = self.properties
        for key in path.split("."):
            if not isinstance(node, dict):
                return default
            node = node.get(key)
        return default if node is None else node


def load(rows: list[dict[str, Any]]) -> list[AzureResource]:
    resources: list[AzureResource] = []
    for row in rows:
        if "type" not in row:
            continue
        resources.append(
            AzureResource(
                id=row.get("id", ""),
                type=str(row["type"]).lower(),
                name=row.get("name", ""),
                resource_group=row.get("resourceGroup", row.get("resource_group", "")),
                location=row.get("location", ""),
                properties=row.get("properties") or {},
            )
        )
    return resources


def load_file(path: str | Path) -> list[AzureResource]:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    # Accept either a bare list or a Resource Graph response {"data": [...]}.
    rows = data.get("data", data) if isinstance(data, dict) else data
    return load(rows)
