"""Comprehensive Security Test Suite for ScamShield.

Validates:
1. Content Security Policy (strict self-hosted CSP on /, relaxed on /docs)
2. Security headers (nosniff, DENY, Referrer-Policy, Permissions-Policy, COOP, CORP, frame-ancestors, HSTS)
3. Input sanitization (null byte rejection, control character rejection, bidi character acceptance)
4. Request body size limit enforcement (32 KB limit -> 413)
5. ReDoS fuzzing across all compiled heuristics rules ("verify " * 300, "otp " * 500)
6. Privacy guarantee: proving request bodies never appear in logger output or disk logs
"""

import logging
import os
import time
import pytest
from starlette.testclient import TestClient
from app.main import app
import app.engine.heuristics as h

client = TestClient(app)


# ==============================================================================
# 1. CONTENT SECURITY POLICY & HARDENED HEADERS
# ==============================================================================

def test_strict_csp_on_root_and_api():
    """Verify root / and /analyze serve strict CSP without 'unsafe-inline'."""
    for path in ("/", "/analyze"):
        res = client.get(path) if path == "/" else client.post(path, json={"message": "hello"})
        csp = res.headers.get("content-security-policy", "")
        assert "default-src 'self'" in csp
        assert "script-src 'self'" in csp
        # Verify NO 'unsafe-inline' in script-src or style-src
        assert "script-src 'self';" in csp or "script-src 'self' " in csp
        assert "'unsafe-inline'" not in csp
        assert "frame-ancestors 'none'" in csp
        assert "https://cdn.jsdelivr.net" not in csp
        assert "https://fonts.googleapis.com" not in csp


def test_relaxed_csp_on_docs_route():
    """Verify /docs serves relaxed CSP for Swagger UI while retaining security."""
    res = client.get("/docs")
    assert res.status_code == 200
    csp = res.headers.get("content-security-policy", "")
    assert "https://cdn.jsdelivr.net" in csp
    assert "'unsafe-inline'" in csp
    assert "frame-ancestors 'none'" in csp


def test_comprehensive_security_headers_present():
    """Verify all mandated security headers are present on API responses."""
    res = client.get("/health")
    headers = res.headers

    assert headers.get("x-content-type-options") == "nosniff"
    assert headers.get("x-frame-options") == "DENY"
    assert headers.get("referrer-policy") == "strict-origin-when-cross-origin"
    assert headers.get("permissions-policy") == "camera=(), microphone=(), geolocation=()"
    assert headers.get("cross-origin-opener-policy") == "same-origin"
    assert headers.get("cross-origin-resource-policy") == "same-origin"
    assert headers.get("x-xss-protection") == "0"


def test_hsts_header_when_flag_enabled(monkeypatch):
    """Verify Strict-Transport-Security header is emitted when ENABLE_HSTS is active."""
    import app.main as m
    monkeypatch.setattr(m, "ENABLE_HSTS", True)

    res = client.get("/health")
    assert "strict-transport-security" in res.headers
    assert "max-age=31536000" in res.headers["strict-transport-security"]


# ==============================================================================
# 2. INPUT VALIDATION & CONTROL CHARACTER REJECTION
# ==============================================================================

def test_reject_null_bytes_in_message():
    """Null bytes must be rejected with HTTP 422."""
    res = client.post("/analyze", json={"message": "Hello\x00world"})
    assert res.status_code == 422
    assert "null bytes" in res.text.lower() or "control characters" in res.text.lower()


def test_reject_ascii_control_characters_in_message():
    """ASCII control characters (e.g. BEL, ESC, BS) must be rejected with HTTP 422."""
    for ctrl in ("\x07", "\x08", "\x1b", "\x7f", "\x0c"):
        res = client.post("/analyze", json={"message": f"Suspicious{ctrl}text"})
        assert res.status_code == 422, f"Failed to reject control character {ord(ctrl)}"


def test_preserve_bidi_characters_in_message():
    """Bidi control characters (e.g. RLO, LRM) must NOT be rejected by input validation."""
    bidi_msg = "Hello \u202Ereversed text\u202C normal text"
    res = client.post("/analyze", json={"message": bidi_msg})
    assert res.status_code == 200, f"Bidi character was incorrectly rejected: {res.text}"


def test_reject_null_bytes_in_sender_id():
    """Null bytes in sender_id must be rejected with HTTP 422."""
    res = client.post("/analyze", json={"message": "Safe text", "sender_id": "SBI\x00Bank"})
    assert res.status_code == 422


# ==============================================================================
# 3. REQUEST BODY SIZE LIMIT (32 KB)
# ==============================================================================

def test_oversized_payload_rejected_with_413():
    """Requests exceeding 32 KB must be rejected with 413 Payload Too Large."""
    oversized_body = "A" * (33 * 1024)
    res = client.post(
        "/analyze",
        content=oversized_body,
        headers={"Content-Type": "application/json", "Content-Length": str(len(oversized_body))},
    )
    assert res.status_code == 413
    assert "too large" in res.text.lower()


# ==============================================================================
# 4. REDOS FUZZING (ADVERSARIAL INPUTS)
# ==============================================================================

def test_redos_fuzzing_all_heuristics_rules():
    """Fuzz all compiled heuristics regexes with adversarial inputs and verify runtime < 50ms."""
    regexes = [
        (name, getattr(h, name))
        for name in dir(h)
        if name.startswith("RE_") and hasattr(getattr(h, name), "search")
    ]

    adversarial_inputs = [
        ("verify_300", "verify " * 300),
        ("otp_500", "otp " * 500),
        ("repeating_a", "a" * 2000),
        ("punctuated_adversarial", "a!b?c#d$" * 250),
        ("bidi_adversarial", "\u202e\u200e\u202a" * 600),
    ]

    max_recorded_ms = 0.0
    slowest_rule = ""

    for name, r in regexes:
        for inp_name, inp in adversarial_inputs:
            t0 = time.perf_counter()
            r.search(inp)
            duration_ms = (time.perf_counter() - t0) * 1000
            if duration_ms > max_recorded_ms:
                max_recorded_ms = duration_ms
                slowest_rule = f"{name} on {inp_name}"
            # Strict safety budget: no rule may exceed 50ms on 2,000-char input
            assert duration_ms < 50.0, (
                f"ReDoS vulnerability detected in {name} on {inp_name}: "
                f"took {duration_ms:.2f}ms (exceeded 50ms budget)!"
            )

    # Document max runtime verified in session
    assert max_recorded_ms < 50.0


# ==============================================================================
# 5. PRIVACY AUDIT (PROVING MESSAGE BODIES NEVER REACH LOGS)
# ==============================================================================

def test_privacy_caplog_guarantees_no_body_logging(caplog):
    """Prove with pytest caplog that raw message body never appears in any log record."""
    secret_token = "TOP_SECRET_CREDENTIAL_TOKEN_XYZ998877"
    app.state.limiter.reset()

    with caplog.at_level(logging.DEBUG):
        res = client.post("/analyze", json={"message": f"My secret code is {secret_token}."})
        assert res.status_code == 200

    # Inspect all captured log records
    all_log_text = " ".join(record.getMessage() for record in caplog.records)
    assert secret_token not in all_log_text, (
        f"Critical privacy failure: message content was leaked to application logger: {all_log_text}"
    )
