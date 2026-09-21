"""The dependency-free ASGI->Lambda adapter, driven against the app with no AWS."""

import json

from endon_soc.app import create_app
from endon_soc.lambda_handler import invoke


def _app(demo_service):
    return create_app(demo_service, region="us-east-1")


def _event(method: str, path: str, query: dict | None = None) -> dict:
    return {
        "httpMethod": method,
        "path": path,
        "queryStringParameters": query,
        "headers": {"host": "soc.example.com"},
        "requestContext": {"identity": {"sourceIp": "10.0.0.1"}},
        "body": None,
        "isBase64Encoded": False,
    }


def test_adapter_returns_json_for_the_api(demo_service):
    response = invoke(_app(demo_service), _event("GET", "/api/summary"))
    assert response["statusCode"] == 200
    assert "application/json" in response["headers"]["content-type"]
    body = json.loads(response["body"])
    assert 0 <= body["security_score"] <= 100


def test_adapter_passes_query_string_through(demo_service):
    response = invoke(_app(demo_service), _event("GET", "/api/incidents", {"status": "CONTAINED"}))
    assert response["statusCode"] == 200
    assert json.loads(response["body"])["count"] == 2


def test_adapter_returns_html_for_the_console(demo_service):
    response = invoke(_app(demo_service), _event("GET", "/"))
    assert response["statusCode"] == 200
    assert "text/html" in response["headers"]["content-type"]
    assert "ENDON AI" in response["body"]


def test_adapter_maps_not_found(demo_service):
    response = invoke(_app(demo_service), _event("GET", "/api/incidents/INC-NOPE"))
    assert response["statusCode"] == 404
