"""Resolve AWS identifiers from finding resources, whichever detector produced them."""

from __future__ import annotations

from endon_core.findings import Resource


def user_name(resource: Resource) -> str:
    return resource.details.get("userName") or resource.name


def role_name(resource: Resource) -> str:
    return resource.details.get("roleName") or resource.name


def instance_id(resource: Resource) -> str:
    return resource.details.get("instanceId") or resource.name


def bucket_name(resource: Resource) -> str:
    return resource.details.get("bucketName") or resource.name


def incident_tags(incident_id: str, status: str) -> list[dict[str, str]]:
    return [
        {"Key": "endon:incident-id", "Value": incident_id},
        {"Key": "endon:incident-status", "Value": status},
    ]
