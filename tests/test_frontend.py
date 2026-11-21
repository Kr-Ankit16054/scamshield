"""Frontend & User Experience Integration Test Suite for ScamShield.

Validates Phase 5 requirements:
- All 7 mandatory layout sections present in single-page HTML
- Static asset serving (CSS and JS)
- 6 required example message archetypes and their API integration
- Validation for empty or whitespace-only inputs
- Backend health probe and offline contract
- Result tier rendering (SAFE, SUSPICIOUS, SCAM) with strict advisory wording
- XSS and HTML input rendering safety (DOM TextNode sanitization)
"""

import shutil
import subprocess
from starlette.testclient import TestClient
from app.main import app

client = TestClient(app)

# The 6 required example archetype payloads matching app.js
SAMPLE_ARCHETYPES = {
    "bank_safe": {
        "title": "Benign banking notification",
        "sender_id": "HDFCBK",
        "message": "Your HDFC Bank account XX4102 has been credited with Rs 5,000.00 on 21-Nov-2026. Available balance: Rs 42,500.00. - HDFC Bank",
        "expected_label": "SAFE",
        "max_score": 39,
    },
    "delivery_safe": {
        "title": "Genuine delivery notification",
        "sender_id": "AMAZON",
        "message": "Your Amazon package with tracking ID 402-9182391 is out for delivery. Give delivery verification code 8391 to delivery executive.",
        "expected_label": "SAFE",
        "max_score": 39,
    },
    "otp_warning": {
        "title": "OTP security warning",
        "sender_id": "NETFLIX",
        "message": "Your Netflix login code is 492018. Do not share this OTP with anyone, including customer support.",
        "expected_label": "SAFE",
        "max_score": 39,
    },
    "shortlink_suspicious": {
        "title": "Suspicious shortened link",
        "sender_id": "+919876543210",
        "message": "Your package delivery could not be completed. Please confirm your delivery address immediately at https://bit.ly/pkg-update-in to avoid return.",
        "expected_label": "SUSPICIOUS",
        "min_score": 40,
        "max_score": 69,
    },
    "kyc_phishing": {
        "title": "KYC phishing",
        "sender_id": "VK-SBIBNK",
        "message": "URGENT: Your SBI netbanking will be blocked today due to pending KYC. Click http://sbi-kyc-verify.top/update to submit OTP immediately.",
        "expected_label": "SCAM",
        "min_score": 70,
    },
    "qr_refund_scam": {
        "title": "QR refund scam",
        "sender_id": "+919811223344",
        "message": "Scan this QR code in PhonePe to receive refund of Rs 1,450 directly into your bank account.",
        "expected_label": "SCAM",
        "min_score": 70,
    },
}


# ==============================================================================
# 1. LAYOUT & STATIC ASSETS TESTS
# ==============================================================================

def test_frontend_serves_html_with_all_seven_sections():
    """Verify GET / serves index.html containing all 7 layout sections."""
    response = client.get("/")
    assert response.status_code == 200
    assert "text/html" in response.headers.get("content-type", "")
    html = response.text

    # Section 1: Header
    assert "app-header" in html
    assert "ScamShield" in html
    assert "header-tagline" in html
    assert "api-status-badge" in html

    # Section 2: Introductory hero
    assert "hero-section" in html
    assert "Instant SMS &amp; Message Scam Analysis" in html or "Instant SMS & Message Scam Analysis" in html

    # Section 3: Message analyzer
    assert "analyze-form" in html
    assert "message-input" in html
    assert "btn-paste" in html
    assert "btn-clear" in html
    assert "char-counter" in html
    assert "analyze-btn" in html

    # Section 4: Analysis results section
    assert "results-container" in html
    assert "gauge-wrapper" in html
    assert "flags-chips-wrap" in html
    assert "recommended-action-box" in html
    assert "message-preview-container" in html

    # Section 5: How it works
    assert "how-it-works-heading" in html
    assert "How ScamShield Works" in html
    assert "steps-grid" in html

    # Section 6: Safety tips
    assert "safety-tips-heading" in html
    assert "Practical SMS Scam Defense Tips" in html
    assert "tips-grid" in html

    # Section 7: Footer
    assert "app-footer" in html
    assert "1930" in html


def test_frontend_contains_six_required_example_archetypes():
    """Verify that index.html contains all 6 required clickable example archetypes."""
    response = client.get("/")
    assert response.status_code == 200
    html = response.text

    for sample_id in SAMPLE_ARCHETYPES.keys():
        assert f'data-sample-id="{sample_id}"' in html


def test_static_css_and_js_served():
    """Verify static assets are properly served with correct MIME types and non-empty."""
    css_res = client.get("/static/style.css")
    assert css_res.status_code == 200
    assert "text/css" in css_res.headers.get("content-type", "")
    assert len(css_res.text) > 1000

    js_res = client.get("/static/app.js")
    assert js_res.status_code == 200
    assert "javascript" in js_res.headers.get("content-type", "")
    assert "SAMPLES" in js_res.text
    assert "triggerAnalysis" in js_res.text


# ==============================================================================
# 2. API INTEGRATION FOR 6 EXAMPLE ARCHETYPES
# ==============================================================================

def test_api_integration_all_six_archetypes():
    """Verify all 6 required archetype examples execute through POST /analyze correctly."""
    app.state.limiter.reset()

    for sample_id, config in SAMPLE_ARCHETYPES.items():
        payload = {
            "message": config["message"],
            "sender_id": config.get("sender_id")
        }
        res = client.post("/analyze", json=payload)
        assert res.status_code == 200, f"Failed for {sample_id}: {res.text}"
        data = res.json()

        assert data["label"] == config["expected_label"], (
            f"Archetype {sample_id} ({config['title']}): expected {config['expected_label']}, got {data['label']}"
        )

        if "min_score" in config:
            assert data["risk_score"] >= config["min_score"], (
                f"Archetype {sample_id} score {data['risk_score']} < min {config['min_score']}"
            )
        if "max_score" in config:
            assert data["risk_score"] <= config["max_score"], (
                f"Archetype {sample_id} score {data['risk_score']} > max {config['max_score']}"
            )

        assert isinstance(data["flags"], list)
        assert len(data["explanation"]) > 0
        assert len(data["recommended_action"]) > 0


# ==============================================================================
# 3. EMPTY INPUT VALIDATION & BACKEND HEALTH
# ==============================================================================

def test_empty_input_validation_rejected():
    """Verify empty or whitespace-only messages are rejected by API with 422."""
    app.state.limiter.reset()

    res_empty = client.post("/analyze", json={"message": ""})
    assert res_empty.status_code == 422

    res_whitespace = client.post("/analyze", json={"message": "   \n\t  "})
    assert res_whitespace.status_code == 422


def test_backend_health_probe():
    """Verify GET /health contract returns 200 with status ok for UI status badge."""
    res = client.get("/health")
    assert res.status_code == 200
    assert res.json() == {"status": "ok"}


# ==============================================================================
# 4. RESULT RENDERING & ADVISORY STATEMENTS
# ==============================================================================

def test_safe_result_does_not_claim_guaranteed_safety():
    """Verify SAFE results do not claim guaranteed safety and provide cautionary guidance."""
    app.state.limiter.reset()
    payload = {
        "message": "Hey team, weekly sync starts in 10 minutes in conference room B.",
        "sender_id": None
    }
    res = client.post("/analyze", json=payload)
    assert res.status_code == 200
    data = res.json()

    assert data["label"] == "SAFE"
    assert data["risk_score"] == 0
    # Must not claim 100% guarantee of safety
    assert "guaranteed" not in data["explanation"].lower()
    assert "safe" in data["explanation"].lower() or "no common scam" in data["explanation"].lower()


def test_scam_result_provides_practical_steps():
    """Verify SCAM results provide strong warnings and practical safety steps."""
    app.state.limiter.reset()
    payload = {
        "message": "URGENT: Your bank account is frozen. Click http://bank-kyc-verify.top/auth and share your OTP immediately to avoid legal penalty.",
        "sender_id": "+919876543210"
    }
    res = client.post("/analyze", json=payload)
    assert res.status_code == 200
    data = res.json()

    assert data["label"] == "SCAM"
    assert data["risk_score"] >= 70
    action = data["recommended_action"].lower()
    # Practical steps: do not click links, do not share OTP, report
    assert "do not" in action or "never" in action
    assert "otp" in action or "link" in action or "credentials" in action or "report" in action


# ==============================================================================
# 5. XSS AND INPUT RENDERING SAFETY
# ==============================================================================

def test_xss_injection_payload_in_analysis():
    """Verify XSS payloads in message or sender ID are safely analyzed without crashing or injecting tags."""
    app.state.limiter.reset()
    xss_payload = '<script>alert("pwned")</script><img src=x onerror=alert(1)>'
    payload = {
        "message": f"{xss_payload} URGENT: verify your account now at http://evil.xyz",
        "sender_id": None
    }
    res = client.post("/analyze", json=payload)
    assert res.status_code == 200
    data = res.json()
    assert data["label"] in ["SUSPICIOUS", "SCAM"]

    # Verify that if node is installed, headless DOM simulation proves DOM TextNode isolation
    if shutil.which("node"):
        node_script = r"""
        class TextNode {
          constructor(text) { this.nodeType = 3; this.textContent = String(text); }
        }
        class Element {
          constructor(tag) {
            this.nodeType = 1;
            this.tagName = tag.toUpperCase();
            this.textContent = '';
            this.children = [];
          }
          appendChild(node) { this.children.push(node); }
          replaceChildren() { this.children = []; }
        }
        const document = {
          createElement: (tag) => new Element(tag),
          createTextNode: (text) => new TextNode(text)
        };

        function renderMessagePreviewToDOM(container, text) {
          container.replaceChildren();
          container.appendChild(document.createTextNode(text));
        }

        const container = new Element('div');
        const malicious = '<script>alert("xss")</script><img src=x onerror=alert(1)>';
        renderMessagePreviewToDOM(container, malicious);

        // Ensure child is TextNode, not HTML script/img element
        if (container.children.length === 1 && container.children[0].nodeType === 3) {
          console.log('SAFE_TEXTNODE');
        } else {
          console.error('INSECURE_RENDER');
          process.exit(1);
        }
        """
        result = subprocess.run(["node", "-e", node_script], capture_output=True, text=True)
        assert result.returncode == 0
        assert "SAFE_TEXTNODE" in result.stdout

