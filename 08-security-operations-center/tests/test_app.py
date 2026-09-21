"""The SOC web application: read-only REST API and server-rendered console."""


def test_summary_endpoint_returns_score_and_counts(client):
    body = client.get("/api/summary").json()
    assert 0 <= body["security_score"] <= 100
    assert body["grade"] in {"A", "B", "C", "D", "F"}
    assert body["severity_counts"]["CRITICAL"] == 1
    assert body["total_incidents"] == 3


def test_incidents_endpoint_lists_and_filters(client):
    all_incidents = client.get("/api/incidents").json()
    assert all_incidents["count"] == 3
    contained = client.get("/api/incidents", params={"status": "CONTAINED"}).json()
    assert contained["count"] == 2


def test_incident_detail_has_timeline_and_404s(client):
    incident_id = client.get("/api/incidents").json()["incidents"][0]["incident_id"]
    detail = client.get(f"/api/incidents/{incident_id}")
    assert detail.status_code == 200
    assert detail.json()["timeline"]
    assert client.get("/api/incidents/INC-NOPE").status_code == 404


def test_findings_endpoint_filters_by_severity(client):
    body = client.get("/api/findings", params={"severity": "HIGH"}).json()
    assert body["count"] >= 1
    assert all(f["severity"] in {"HIGH", "CRITICAL"} for f in body["findings"])


def test_api_is_read_only_no_mutating_verbs(client):
    # A dashboard must not offer a way to change platform state.
    assert client.post("/api/incidents").status_code in (404, 405)
    assert client.delete("/api/incidents/INC-1").status_code in (404, 405)
    assert client.put("/api/findings").status_code in (404, 405)


def test_dashboard_page_renders_html(client):
    resp = client.get("/")
    assert resp.status_code == 200
    assert "text/html" in resp.headers["content-type"]
    assert "SECURITY OPERATIONS" in resp.text.upper()
    assert "Recent incidents" in resp.text


def test_incident_page_renders_and_escapes(client):
    incident_id = client.get("/api/incidents").json()["incidents"][0]["incident_id"]
    resp = client.get(f"/incidents/{incident_id}")
    assert resp.status_code == 200
    assert "Timeline" in resp.text
    assert client.get("/incidents/INC-NOPE").status_code == 404


def test_healthz(client):
    assert client.get("/healthz").json() == {"status": "ok"}
