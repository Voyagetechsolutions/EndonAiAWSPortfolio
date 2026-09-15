"""boto3 client creation and small AWS helpers shared by all components."""

from __future__ import annotations

from typing import Any

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError

_BOTO_CONFIG = Config(
    retries={"max_attempts": 8, "mode": "adaptive"},
    user_agent_extra="endon-ai/0.1",
)


class ClientFactory:
    """Creates boto3 clients for one region and reuses them across calls.

    Components receive a factory instead of building clients themselves, which
    keeps them testable and lets a Lambda reuse connections between invocations.
    """

    def __init__(self, region: str | None = None, session: boto3.session.Session | None = None):
        self.region = region
        self._session = session
        self._clients: dict[str, Any] = {}

    def __call__(self, service: str) -> Any:
        if service not in self._clients:
            session = self._session or boto3.session.Session()
            self._clients[service] = session.client(
                service, region_name=self.region, config=_BOTO_CONFIG
            )
        return self._clients[service]


def error_code(exc: BaseException) -> str:
    if isinstance(exc, ClientError):
        return exc.response.get("Error", {}).get("Code", "")
    return ""


def role_names_from_arn(arn: str) -> frozenset[str]:
    """Role name behind a role or assumed-role ARN; empty for any other principal."""
    resource = arn.split(":", 5)[-1]
    if resource.startswith("assumed-role/"):
        return frozenset({resource.split("/")[1]})
    if resource.startswith("role/"):
        return frozenset({resource.rsplit("/", 1)[-1]})
    return frozenset()
