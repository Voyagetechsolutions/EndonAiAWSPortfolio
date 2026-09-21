"""Run the ASGI app on AWS Lambda behind API Gateway - with no extra runtime dependency.

Rather than pull in an ASGI adapter, the SOC ships a small one. It translates an API Gateway
REST proxy event into an ASGI ``http`` scope, drives the FastAPI app to completion, and maps
the response back. That keeps the Lambda bundle to Endon's own packages plus the runtime's
boto3 (the platform's dependency discipline), and it is itself unit-tested against the app.

``handler`` is the deployed entry point; it builds the live, DynamoDB-backed app once per cold
start. ``invoke`` is the pure adapter, so tests exercise it against an in-memory app with no AWS.
"""

from __future__ import annotations

import asyncio
from base64 import b64decode
from typing import Any
from urllib.parse import urlencode

_app: Any = None


def handler(event: dict[str, Any], context: Any = None) -> dict[str, Any]:
    """Deployed Lambda entry point: build the live app once, then adapt each request."""
    global _app
    if _app is None:
        from endon_core.aws import ClientFactory
        from endon_core.config import Settings
        from endon_soc.app import create_app
        from endon_soc.wiring import build_live_service

        settings = Settings.from_env()
        service = build_live_service(settings, ClientFactory(region=settings.region))
        _app = create_app(service, region=settings.region)
    return invoke(_app, event)


def invoke(app: Any, event: dict[str, Any]) -> dict[str, Any]:
    """Drive an ASGI app for one API Gateway REST proxy event and return the proxy response."""
    scope, body = _scope_from_event(event)
    return asyncio.run(_run(app, scope, body))


def _scope_from_event(event: dict[str, Any]) -> tuple[dict[str, Any], bytes]:
    method = event.get("httpMethod", "GET")
    path = event.get("path", "/")
    query_string = _query_string(event).encode("utf-8")
    headers = _headers(event)
    body = event.get("body") or ""
    body_bytes = b64decode(body) if event.get("isBase64Encoded") else body.encode("utf-8")
    source_ip = (event.get("requestContext", {}).get("identity", {}) or {}).get("sourceIp", "")

    scope = {
        "type": "http",
        "asgi": {"version": "3.0", "spec_version": "2.3"},
        "http_version": "1.1",
        "method": method,
        "scheme": "https",
        "path": path,
        "raw_path": path.encode("utf-8"),
        "query_string": query_string,
        "root_path": "",
        "headers": [(k.lower().encode("utf-8"), v.encode("utf-8")) for k, v in headers],
        "server": (headers_get(headers, "host", "localhost"), 443),
        "client": (source_ip, 0),
    }
    return scope, body_bytes


def _query_string(event: dict[str, Any]) -> str:
    multi = event.get("multiValueQueryStringParameters")
    if multi:
        return urlencode([(k, v) for k, values in multi.items() for v in values])
    single = event.get("queryStringParameters") or {}
    return urlencode({k: v for k, v in single.items() if v is not None})


def _headers(event: dict[str, Any]) -> list[tuple[str, str]]:
    multi = event.get("multiValueHeaders")
    if multi:
        return [(k, v) for k, values in multi.items() for v in values]
    return list((event.get("headers") or {}).items())


def headers_get(headers: list[tuple[str, str]], name: str, default: str) -> str:
    for key, value in headers:
        if key.lower() == name:
            return value
    return default


async def _run(app: Any, scope: dict[str, Any], body: bytes) -> dict[str, Any]:
    status = 500
    raw_headers: list[tuple[bytes, bytes]] = []
    chunks: list[bytes] = []
    request_sent = False

    async def receive() -> dict[str, Any]:
        nonlocal request_sent
        if request_sent:
            return {"type": "http.disconnect"}
        request_sent = True
        return {"type": "http.request", "body": body, "more_body": False}

    async def send(message: dict[str, Any]) -> None:
        nonlocal status, raw_headers
        if message["type"] == "http.response.start":
            status = message["status"]
            raw_headers = message.get("headers", [])
        elif message["type"] == "http.response.body":
            chunks.append(message.get("body", b""))

    await app(scope, receive, send)

    response_headers = {k.decode("latin-1"): v.decode("latin-1") for k, v in raw_headers}
    return {
        "statusCode": status,
        "headers": response_headers,
        "body": b"".join(chunks).decode("utf-8"),
        "isBase64Encoded": False,
    }
