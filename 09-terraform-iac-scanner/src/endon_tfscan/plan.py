"""Parse a Terraform plan into the resources the scanner evaluates.

The scanner reads the JSON that ``terraform show -json plan.out`` emits, not raw HCL. That
is the right layer to check: the plan is what Terraform will actually create, with every
variable, default and module resolved — so a rule sees the real value of an attribute, not
an unresolved expression. It is also plain JSON, so parsing needs nothing but the standard
library, and the same fixtures drive the tests with no Terraform binary in the loop.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class Resource:
    """One planned resource: its address, type, and the config Terraform will apply."""

    address: str
    type: str
    name: str
    provider: str
    actions: tuple[str, ...]
    values: dict[str, Any]

    @property
    def is_destroy(self) -> bool:
        return tuple(self.actions) == ("delete",)

    @property
    def is_noop(self) -> bool:
        return tuple(self.actions) == ("no-op",)

    def get(self, key: str, default: Any = None) -> Any:
        return self.values.get(key, default)

    def blocks(self, key: str) -> list[dict[str, Any]]:
        """A nested block as a list of dicts (Terraform renders blocks as JSON arrays)."""
        raw = self.values.get(key)
        if raw is None:
            return []
        return raw if isinstance(raw, list) else [raw]


@dataclass(frozen=True)
class Plan:
    resources: tuple[Resource, ...]
    terraform_version: str = ""

    def of_type(self, *types: str) -> list[Resource]:
        wanted = set(types)
        return [r for r in self.resources if r.type in wanted]

    @classmethod
    def from_json(cls, document: dict[str, Any]) -> Plan:
        resources: list[Resource] = []
        for change in document.get("resource_changes", []):
            if change.get("mode") != "managed":
                continue  # skip data sources
            detail = change.get("change", {})
            actions = tuple(detail.get("actions", []))
            resource = Resource(
                address=change.get("address", ""),
                type=change.get("type", ""),
                name=change.get("name", ""),
                provider=_short_provider(change.get("provider_name", "")),
                actions=actions,
                values=detail.get("after") or {},
            )
            # Nothing is being created or changed, so there is nothing to flag.
            if resource.is_destroy or resource.is_noop:
                continue
            resources.append(resource)
        return cls(tuple(resources), document.get("terraform_version", ""))

    @classmethod
    def from_file(cls, path: str | Path) -> Plan:
        return cls.from_json(json.loads(Path(path).read_text(encoding="utf-8")))


def _short_provider(provider_name: str) -> str:
    """`registry.terraform.io/hashicorp/aws` -> `aws`."""
    return provider_name.rsplit("/", 1)[-1] if provider_name else ""
