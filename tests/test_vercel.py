"""Tests for Vercel deployment architecture, entrypoint adapter, and route routing.

Verifies:
1. `api.index:app` correctly exposes the FastAPI application instance
2. `/` serves the single-page application with ScamShield title
3. `/health` responds with HTTP 200 {"status": "ok"}
4. `/analyze` deterministic smishing heuristic analysis executes correctly
5. `/docs` OpenAPI Swagger UI is accessible
6. `/openapi.json` OpenAPI schema specification is accessible
7. `/static/style.css` and `/static/app.js` are properly served
8. `.python-version` correctly specifies supported Python version
9. `vercel.json` contains valid configuration with includeFiles and rewrites
"""

import json
from pathlib import Path
from starlette.testclient import TestClient

from api.index import app as vercel_app

client = TestClient(vercel_app)
PROJECT_ROOT = Path(__file__).resolve().parent.parent


def test_vercel_entrypoint_instance():
    """Verify api.index:app is a valid FastAPI application."""
    from fastapi import FastAPI
    assert isinstance(vercel_app, FastAPI)
    assert vercel_app.title == "ScamShield API"


def test_vercel_route_root():
    """Verify route / returns HTTP 200 with HTML content containing ScamShield."""
    res = client.get("/")
    assert res.status_code == 200
    assert "text/html" in res.headers.get("content-type", "")
    assert "ScamShield" in res.text


def test_vercel_route_health():
    """Verify route /health returns HTTP 200 with status ok."""
    res = client.get("/health")
    assert res.status_code == 200
    assert res.json() == {"status": "ok"}


def test_vercel_route_analyze():
    """Verify route /analyze accepts requests and returns deterministic risk evaluation."""
    vercel_app.state.limiter.reset()
    payload = {
        "message": "URGENT: Your SBI account is blocked. Update KYC immediately at bit.ly/fake-sbi",
        "sender_id": "VK-SBIINB"
    }
    res = client.post("/analyze", json=payload)
    assert res.status_code == 200
    data = res.json()
    assert "risk_score" in data
    assert "label" in data
    assert "flags" in data
    assert "explanation" in data
    assert "recommended_action" in data
    assert data["label"].upper() in ["SUSPICIOUS", "SCAM"]
    assert data["risk_score"] >= 40


def test_vercel_route_docs():
    """Verify route /docs serves OpenAPI Swagger UI."""
    res = client.get("/docs")
    assert res.status_code == 200
    assert "text/html" in res.headers.get("content-type", "")


def test_vercel_route_openapi():
    """Verify route /openapi.json serves valid OpenAPI 3 specification."""
    res = client.get("/openapi.json")
    assert res.status_code == 200
    schema = res.json()
    assert "openapi" in schema
    assert "paths" in schema
    assert "/health" in schema["paths"]
    assert "/analyze" in schema["paths"]


def test_vercel_route_static_css():
    """Verify route /static/style.css serves non-empty stylesheet."""
    res = client.get("/static/style.css")
    assert res.status_code == 200
    assert len(res.text) > 0


def test_vercel_route_static_js():
    """Verify route /static/app.js serves non-empty JavaScript."""
    res = client.get("/static/app.js")
    assert res.status_code == 200
    assert len(res.text) > 0


def test_python_version_file():
    """Verify .python-version file exists and specifies supported version 3.12 without patch."""
    version_file = PROJECT_ROOT / ".python-version"
    assert version_file.exists(), ".python-version file must exist"
    content = version_file.read_text().strip()
    assert content == "3.12", f"Expected '3.12' in .python-version, got '{content}'"


def test_vercel_json_configuration():
    """Verify vercel.json is valid JSON with required functions and rewrites keys."""
    config_file = PROJECT_ROOT / "vercel.json"
    assert config_file.exists(), "vercel.json must exist"
    data = json.loads(config_file.read_text())
    
    # Check functions block
    assert "functions" in data, "vercel.json must contain 'functions'"
    assert "api/index.py" in data["functions"]
    assert "includeFiles" in data["functions"]["api/index.py"]
    assert data["functions"]["api/index.py"]["includeFiles"] == "app/static/**"
    
    # Check rewrites block
    assert "rewrites" in data, "vercel.json must contain 'rewrites'"
    rewrites = data["rewrites"]
    assert len(rewrites) >= 1
    assert rewrites[0]["source"] == "/(.*)"
    assert rewrites[0]["destination"] == "/api/index.py"
