"""Persistence for incidents and findings.

DynamoDB stores each record as a JSON document plus a few top-level attributes
for querying. Keeping the document whole lets the schema evolve without
migrations and sidesteps DynamoDB's float/Decimal conversion. The in-memory
stores round-trip through the same serialization so tests catch mapping bugs.
"""

from __future__ import annotations

import json
from typing import Any, Protocol

from botocore.exceptions import ClientError

from endon_core.aws import error_code
from endon_core.findings import Finding
from endon_core.incidents import Incident


class IncidentStore(Protocol):
    def create(self, incident: Incident) -> bool:
        """Persist a new incident. Returns False if it already exists."""
        ...

    def save(self, incident: Incident) -> None: ...

    def get(self, incident_id: str) -> Incident | None: ...

    def list(self, limit: int = 100) -> list[Incident]: ...


class FindingStore(Protocol):
    def save(self, finding: Finding) -> None: ...

    def get(self, finding_id: str) -> Finding | None: ...

    def list(self, limit: int = 100) -> list[Finding]: ...


class _DocumentTable:
    def __init__(self, table_name: str, key: str, client: Any) -> None:
        self.table_name = table_name
        self.key = key
        self._client = client

    def put(
        self,
        key_value: str,
        document: dict[str, Any],
        attributes: dict[str, Any],
        only_if_new: bool = False,
    ) -> bool:
        item = {self.key: {"S": key_value}, "document": {"S": json.dumps(document, default=str)}}
        item.update({k: {"S": str(v)} for k, v in attributes.items() if v is not None})
        request: dict[str, Any] = {"TableName": self.table_name, "Item": item}
        if only_if_new:
            request["ConditionExpression"] = "attribute_not_exists(#key)"
            request["ExpressionAttributeNames"] = {"#key": self.key}
        try:
            self._client.put_item(**request)
        except ClientError as exc:
            if only_if_new and error_code(exc) == "ConditionalCheckFailedException":
                return False
            raise
        return True

    def get(self, key_value: str) -> dict[str, Any] | None:
        response = self._client.get_item(
            TableName=self.table_name, Key={self.key: {"S": key_value}}, ConsistentRead=True
        )
        item = response.get("Item")
        return json.loads(item["document"]["S"]) if item else None

    def scan(self, limit: int) -> list[dict[str, Any]]:
        documents: list[dict[str, Any]] = []
        request: dict[str, Any] = {
            "TableName": self.table_name,
            "ProjectionExpression": "#doc",
            "ExpressionAttributeNames": {"#doc": "document"},
        }
        while len(documents) < limit:
            page = self._client.scan(**request)
            documents.extend(json.loads(i["document"]["S"]) for i in page.get("Items", []))
            if "LastEvaluatedKey" not in page:
                break
            request["ExclusiveStartKey"] = page["LastEvaluatedKey"]
        return documents[:limit]


class DynamoDBIncidentStore:
    def __init__(self, table_name: str, client: Any) -> None:
        self._table = _DocumentTable(table_name, "incident_id", client)

    def create(self, incident: Incident) -> bool:
        return self._table.put(
            incident.incident_id,
            incident.to_dict(),
            _incident_attributes(incident),
            only_if_new=True,
        )

    def save(self, incident: Incident) -> None:
        self._table.put(incident.incident_id, incident.to_dict(), _incident_attributes(incident))

    def get(self, incident_id: str) -> Incident | None:
        document = self._table.get(incident_id)
        return Incident.from_dict(document) if document else None

    def list(self, limit: int = 100) -> list[Incident]:
        incidents = [Incident.from_dict(d) for d in self._table.scan(limit)]
        return sorted(incidents, key=lambda i: i.opened_at, reverse=True)


class DynamoDBFindingStore:
    def __init__(self, table_name: str, client: Any) -> None:
        self._table = _DocumentTable(table_name, "finding_id", client)

    def save(self, finding: Finding) -> None:
        self._table.put(finding.id, finding.to_dict(), _finding_attributes(finding))

    def get(self, finding_id: str) -> Finding | None:
        document = self._table.get(finding_id)
        return Finding.from_dict(document) if document else None

    def list(self, limit: int = 100) -> list[Finding]:
        findings = [Finding.from_dict(d) for d in self._table.scan(limit)]
        return sorted(findings, key=lambda f: f.updated_at, reverse=True)


class InMemoryIncidentStore:
    def __init__(self) -> None:
        self._items: dict[str, str] = {}

    def create(self, incident: Incident) -> bool:
        if incident.incident_id in self._items:
            return False
        self.save(incident)
        return True

    def save(self, incident: Incident) -> None:
        self._items[incident.incident_id] = json.dumps(incident.to_dict(), default=str)

    def get(self, incident_id: str) -> Incident | None:
        raw = self._items.get(incident_id)
        return Incident.from_dict(json.loads(raw)) if raw else None

    def list(self, limit: int = 100) -> list[Incident]:
        incidents = [Incident.from_dict(json.loads(raw)) for raw in self._items.values()]
        return sorted(incidents, key=lambda i: i.opened_at, reverse=True)[:limit]


class InMemoryFindingStore:
    def __init__(self) -> None:
        self._items: dict[str, str] = {}

    def save(self, finding: Finding) -> None:
        self._items[finding.id] = json.dumps(finding.to_dict(), default=str)

    def get(self, finding_id: str) -> Finding | None:
        raw = self._items.get(finding_id)
        return Finding.from_dict(json.loads(raw)) if raw else None

    def list(self, limit: int = 100) -> list[Finding]:
        findings = [Finding.from_dict(json.loads(raw)) for raw in self._items.values()]
        return sorted(findings, key=lambda f: f.updated_at, reverse=True)[:limit]


def _incident_attributes(incident: Incident) -> dict[str, Any]:
    return {
        "status": incident.status.value,
        "severity": incident.finding.severity.value,
        "playbook": incident.playbook,
        "opened_at": incident.opened_at,
    }


def _finding_attributes(finding: Finding) -> dict[str, Any]:
    return {
        "source": finding.source,
        "type": finding.type,
        "severity": finding.severity.value,
        "updated_at": finding.updated_at,
    }
