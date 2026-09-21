"""The SOC web application: a read-only REST API and server-rendered console.

The API and the HTML pages are two views of the same ``SocService``. Everything is a GET;
there is no route that mutates platform state, by construction. The app is built by a factory
so tests can inject an in-memory service and the Lambda handler can inject a DynamoDB-backed
one, with no globals and no import-time AWS calls.
"""

from __future__ import annotations

from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse

from endon_soc.render import render
from endon_soc.service import SocService


def create_app(service: SocService, *, account_id: str = "", region: str = "") -> FastAPI:
    app = FastAPI(
        title="Endon AI Security Operations Center",
        description="Read-only view over the Endon AI platform's findings and incidents.",
        version="0.1.0",
    )

    # ---- REST API ---------------------------------------------------------------
    @app.get("/healthz")
    def healthz() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/api/summary")
    def api_summary() -> dict[str, object]:
        return service.summary().to_dict()

    @app.get("/api/incidents")
    def api_incidents(status: str | None = None, limit: int = 100) -> dict[str, object]:
        incidents = service.incidents(status=status, limit=limit)
        return {
            "count": len(incidents),
            "incidents": [i.to_dict(include_raw=False) for i in incidents],
        }

    @app.get("/api/incidents/{incident_id}")
    def api_incident(incident_id: str) -> dict[str, object]:
        incident = service.incident(incident_id)
        if incident is None:
            raise HTTPException(status_code=404, detail="incident not found")
        return incident.to_dict(include_raw=False)

    @app.get("/api/findings")
    def api_findings(
        severity: str | None = None, source: str | None = None, limit: int = 100
    ) -> dict[str, object]:
        findings = service.findings(severity=severity, source=source, limit=limit)
        return {
            "count": len(findings),
            "findings": [f.to_dict(include_raw=False) for f in findings],
        }

    # ---- Server-rendered console ------------------------------------------------
    @app.get("/", response_class=HTMLResponse)
    def dashboard() -> str:
        summary = service.summary()
        incidents = service.incidents(limit=25)
        return render(
            "dashboard.html",
            summary=summary,
            incidents=incidents,
            account_id=account_id,
            region=region,
            generated_at=summary.generated_at,
        )

    @app.get("/incidents/{incident_id}", response_class=HTMLResponse)
    def incident_page(incident_id: str) -> str:
        incident = service.incident(incident_id)
        if incident is None:
            raise HTTPException(status_code=404, detail="incident not found")
        return render(
            "incident.html",
            incident=incident,
            account_id=account_id,
            region=region,
        )

    return app
