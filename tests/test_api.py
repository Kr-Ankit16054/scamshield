"""Integration and endpoint test suite for ScamShield FastAPI application.

Validates:
- Health check endpoint
- Message analysis endpoint with valid inputs (scam, suspicious, safe)
- Strict validation: empty message (0), message length 2001, exactly 2000, invalid sender ID, missing message key
- Security headers (X-Content-Type-Options: nosniff, X-Frame-Options: DENY, CSP, X-XSS-Protection: 0) on /, /analyze, /health
- Rate limiting enforcement (1-30 return 200, 31-35 return 429) and health exempt
- Zero log leaks of message content
- Static files and root UI endpoint
"""

import io
import sys
import glob
import pytest
from starlette.testclient import TestClient
from app.main import app

client = TestClient(app)


def test_health_endpoint():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_analyze_scam_message():
    app.state.limiter.reset()
    payload = {
        "message": "URGENT: SBI Bank alert! Your account is suspended. Update KYC now at https://sbi-bank.xyz/login and share OTP immediately.",
        "sender_id": "+919876543210"
    }
    response = client.post("/analyze", json=payload)
    assert response.status_code == 200
    data = response.json()

    assert "risk_score" in data
    assert "label" in data
    assert "flags" in data
    assert "explanation" in data
    assert "recommended_action" in data

    assert data["risk_score"] >= 70
    assert data["label"] == "SCAM"
    assert len(data["flags"]) >= 3
    assert any(f["id"] == "OTP_CREDENTIAL_REQUEST" for f in data["flags"])
    assert any(f["id"] == "SUSPICIOUS_LINK" for f in data["flags"])
    assert any(f["id"] == "URGENCY_PRESSURE" for f in data["flags"])


def test_analyze_safe_message():
    app.state.limiter.reset()
    payload = {
        "message": "Hey Rahul, let's catch up tomorrow at 5 PM at the library to review our project.",
        "sender_id": None
    }
    response = client.post("/analyze", json=payload)
    assert response.status_code == 200
    data = response.json()

    assert data["risk_score"] == 0
    assert data["label"] == "SAFE"
    assert len(data["flags"]) == 0
    assert "No common scam patterns" in data["explanation"]


def test_analyze_suspicious_message():
    app.state.limiter.reset()
    payload = {
        "message": "Dear customer, action required immediately regarding your uncollected package. Check details at bit.ly/3x892.",
        "sender_id": None
    }
    response = client.post("/analyze", json=payload)
    assert response.status_code == 200
    data = response.json()

    assert 40 <= data["risk_score"] <= 69
    assert data["label"] == "SUSPICIOUS"
    assert len(data["flags"]) >= 1


# ==============================================================================
# INPUT VALIDATION (5 REQUIRED CASES)
# ==============================================================================

def test_validation_empty_message():
    """Case 1: Message length 0 -> 422"""
    payload = {"message": ""}
    response = client.post("/analyze", json=payload)
    assert response.status_code == 422


def test_validation_message_too_long():
    """Case 2: Message length 2001 -> 422"""
    payload = {"message": "A" * 2001}
    response = client.post("/analyze", json=payload)
    assert response.status_code == 422


def test_validation_message_exactly_2000():
    """Case 3: Message length exactly 2000 -> 200"""
    app.state.limiter.reset()
    payload = {"message": "A" * 2000}
    response = client.post("/analyze", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert "risk_score" in data


def test_validation_invalid_sender_id():
    """Case 4: sender_id containing invalid characters -> 422"""
    payload = {
        "message": "Meeting at 4pm",
        "sender_id": "Bad<script>alert(1)</script>"
    }
    response = client.post("/analyze", json=payload)
    assert response.status_code == 422


def test_validation_missing_message_key():
    """Case 5: JSON body missing 'message' key -> 422"""
    payload = {"sender_id": "AX-HDFCBK"}
    response = client.post("/analyze", json=payload)
    assert response.status_code == 422


# ==============================================================================
# SECURITY HEADERS
# ==============================================================================

@pytest.mark.parametrize("path,method,body", [
    ("/", "GET", None),
    ("/health", "GET", None),
    ("/analyze", "POST", {"message": "Routine check"}),
])
def test_security_headers_present_on_all_endpoints(path, method, body):
    """Every response on /, /health, /analyze must include hardened security headers."""
    app.state.limiter.reset()
    if method == "GET":
        response = client.get(path)
    else:
        response = client.post(path, json=body)

    assert response.status_code == 200
    headers = response.headers

    assert headers.get("x-content-type-options") == "nosniff"
    assert headers.get("x-frame-options") == "DENY"
    assert "default-src" in headers.get("content-security-policy", "")
    assert headers.get("x-xss-protection") == "0"


def test_static_root_endpoint():
    response = client.get("/")
    assert response.status_code == 200
    assert "text/html" in response.headers.get("content-type", "")


def test_docs_csp_allows_swagger_assets():
    """Verify /docs response includes CSP allowing Swagger UI assets from cdn.jsdelivr.net."""
    response = client.get("/docs")
    assert response.status_code == 200
    csp = response.headers.get("content-security-policy", "")
    assert "https://cdn.jsdelivr.net" in csp
    # Verify allowed specifically under script-src and style-src
    assert "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net;" in csp
    assert "https://cdn.jsdelivr.net" in csp.split("style-src")[1].split(";")[0]


# ==============================================================================
# RATE LIMITING
# ==============================================================================

def test_rate_limiting_exact_boundary():
    """35 rapid requests to POST /analyze: 1-30 return 200, 31-35 return 429."""
    app.state.limiter.reset()
    statuses = []
    for i in range(35):
        res = client.post("/analyze", json={"message": f"Message {i}"})
        statuses.append(res.status_code)

    assert statuses[:30] == [200] * 30, f"Expected first 30 requests to be 200, got: {statuses[:30]}"
    assert statuses[30:] == [429] * 5, f"Expected requests 31-35 to be 429, got: {statuses[30:]}"


def test_health_endpoint_not_rate_limited():
    """Verify GET /health is NOT rate limited even after 35 rapid requests."""
    app.state.limiter.reset()
    statuses = [client.get("/health").status_code for _ in range(35)]
    assert all(s == 200 for s in statuses), "GET /health should never be rate limited"


# ==============================================================================
# PRIVACY / NO LOG LEAKS
# ==============================================================================

def test_privacy_no_message_log_leaks():
    """Send message with unique marker and assert it never appears in logs or stdout."""
    marker = "ZZTESTMARKER123"
    captured_stdout = io.StringIO()
    old_stdout = sys.stdout
    sys.stdout = captured_stdout

    try:
        app.state.limiter.reset()
        res = client.post("/analyze", json={"message": f"Confidential text {marker} please protect"})
        assert res.status_code == 200
    finally:
        sys.stdout = old_stdout

    # Assert marker not captured in stdout
    stdout_text = captured_stdout.getvalue()
    assert marker not in stdout_text, f"Security leak: '{marker}' found in stdout output!"

    # Assert marker not written to any .log file
    for log_path in glob.glob("**/*.log", recursive=True):
        with open(log_path, "r", errors="ignore") as lf:
            content = lf.read()
            assert marker not in content, f"Security leak: '{marker}' found in log file {log_path}!"


# ==============================================================================
# PHASE 2: EVASION DETECTION ENDPOINT TESTS
# ==============================================================================

def test_api_analyze_evasive_obfuscated_scam():
    """Verify endpoint identifies obfuscated OTP, spaced KYC, and remote access scams as SCAM."""
    app.state.limiter.reset()
    payload = {
        "message": "URGENTTTTT: Your K.Y.C. is suspended. Install AnyDesk app and share your O T P immediately to restore access.",
        "sender_id": "+919876543210"
    }
    response = client.post("/analyze", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["label"] == "SCAM"
    assert data["risk_score"] >= 70
    assert any(f["id"] == "REMOTE_ACCESS_APP" for f in data["flags"])
    assert any(f["id"] == "OTP_CREDENTIAL_REQUEST" for f in data["flags"])


def test_api_analyze_benign_hinglish_message():
    """Verify endpoint classifies everyday benign Hinglish conversation as SAFE (score 0)."""
    app.state.limiter.reset()
    payload = {
        "message": "Bhai kal lunch par chalein? Mujhe batao aur venue decide kar lo.",
        "sender_id": None
    }
    response = client.post("/analyze", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["label"] == "SAFE"
    assert data["risk_score"] == 0
    assert len(data["flags"]) == 0


def test_api_analyze_security_warning_with_evasive_otp():
    """Verify endpoint treats genuine security warnings with spaced OTP as SAFE."""
    app.state.limiter.reset()
    payload = {
        "message": "Security Alert: Never share your O T P or netbanking password with anyone.",
        "sender_id": "AX-HDFCBK"
    }
    response = client.post("/analyze", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["label"] == "SAFE"
    assert data["risk_score"] < 40
    assert not any(f["id"] == "OTP_CREDENTIAL_REQUEST" for f in data["flags"])
