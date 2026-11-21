"""ScamShield Main Application.

Production-ready FastAPI service featuring:
- Strict input validation via Pydantic v2 schemas
- Deterministic heuristic analysis engine + natural language explainer
- SlowAPI IP-based rate limiting (30 requests/minute/IP)
- Security headers middleware (CSP, X-Content-Type-Options, X-Frame-Options, XSS protection)
- Privacy-first zero disk logging of message contents
- Accessible static single-page application serving
"""

import logging
import os
import time
from pathlib import Path
from typing import Annotated

from fastapi import FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address

try:
    from app.engine.explainer import generate_explanation, generate_recommended_action
    from app.engine.heuristics import run_all_heuristics
    from app.engine.scorer import evaluate_flags
    from app.schemas import AnalyzeRequest, AnalyzeResponse, HealthResponse
except ModuleNotFoundError:
    from scamshield.app.engine.explainer import generate_explanation, generate_recommended_action
    from scamshield.app.engine.heuristics import run_all_heuristics
    from scamshield.app.engine.scorer import evaluate_flags
    from scamshield.app.schemas import AnalyzeRequest, AnalyzeResponse, HealthResponse

# ==============================================================================
# LOGGING SETUP (SECURITY: ZERO MESSAGE CONTENT LOGGING)
# ==============================================================================
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("scamshield")

# ==============================================================================
# ENVIRONMENT & CONFIGURATION (RENDER & PRODUCTION COMPATIBLE)
# ==============================================================================
HOST = os.environ.get("HOST", "0.0.0.0")  # nosec B104
PORT = int(os.environ.get("PORT", "8000"))
RATE_LIMIT_PER_MINUTE = os.environ.get("RATE_LIMIT_PER_MINUTE", "30")
ALLOWED_ORIGINS = os.environ.get("ALLOWED_ORIGINS", "*")
DOCS_ENABLED = os.environ.get("DOCS_ENABLED", "true").lower() in ("true", "1", "yes")
ENABLE_HSTS = os.environ.get("ENABLE_HSTS", "false").lower() in ("true", "1", "yes")
MAX_REQUEST_BODY_BYTES = 32 * 1024  # 32 KB limit

# ==============================================================================
# RATE LIMITING & APP INITIALIZATION
# ==============================================================================
limiter = Limiter(key_func=get_remote_address, default_limits=[f"{RATE_LIMIT_PER_MINUTE}/minute"])

app = FastAPI(
    title="ScamShield API",
    version="1.0.0",
    description="Suspicious Message & Smishing Detector Heuristic Risk Analysis API",
    docs_url="/docs" if DOCS_ENABLED else None,
    redoc_url="/redoc" if DOCS_ENABLED else None,
    openapi_url="/openapi.json" if DOCS_ENABLED else None,
)

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# ==============================================================================
# CORS CONFIGURATION
# ==============================================================================
parsed_origins = [o.strip() for o in ALLOWED_ORIGINS.split(",") if o.strip()]
app.add_middleware(
    CORSMiddleware,
    allow_origins=parsed_origins if parsed_origins else ["*"],
    allow_credentials=False,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
)


# ==============================================================================
# SECURITY HEADERS, BODY LIMIT & AUDIT MIDDLEWARE
# ==============================================================================
@app.middleware("http")
async def security_and_audit_middleware(request: Request, call_next):
    """Enforces 32 KB body limit, adds hardened security headers, and logs metadata only."""
    # 1. Enforce 32 KB request body limit
    content_length = request.headers.get("content-length")
    if content_length:
        try:
            if int(content_length) > MAX_REQUEST_BODY_BYTES:
                return JSONResponse(
                    status_code=status.HTTP_413_CONTENT_TOO_LARGE,
                    content={"detail": "Payload too large. Maximum allowed request body size is 32 KB."},
                )
        except ValueError:
            pass

    start_time = time.perf_counter()
    response = await call_next(request)
    duration_ms = (time.perf_counter() - start_time) * 1000

    # Privacy: Log ONLY metadata (client IP, path, status, latency) - NEVER message payload
    client_ip = get_remote_address(request) or "unknown"
    logger.info(
        f"Handled {request.method} {request.url.path} from {client_ip} "
        f"-> Status {response.status_code} in {duration_ms:.2f}ms"
    )

    # Hardened Security Headers
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
    response.headers["Cross-Origin-Resource-Policy"] = "same-origin"
    # Modern OWASP best practice: disable legacy buggy XSS auditor in favor of CSP
    response.headers["X-XSS-Protection"] = "0"

    if ENABLE_HSTS or request.url.scheme == "https":
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"

    # Context-aware Content Security Policy (strict self-hosted CSP on application, relaxed for Swagger docs)
    is_docs_route = request.url.path in ("/docs", "/redoc", "/openapi.json")
    if is_docs_route:
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
            "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
            "img-src 'self' data: https://fastapi.tiangolo.com; "
            "connect-src 'self'; "
            "frame-ancestors 'none';"
        )
    else:
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self'; "
            "style-src 'self'; "
            "font-src 'self'; "
            "img-src 'self' data:; "
            "connect-src 'self'; "
            "frame-ancestors 'none'; "
            "base-uri 'self'; "
            "form-action 'self';"
        )

    return response


# ==============================================================================
# API ENDPOINTS
# ==============================================================================
@app.api_route("/health", methods=["GET", "HEAD"], response_model=HealthResponse, tags=["Health"])
async def health_check() -> HealthResponse:
    """Service health probe endpoint."""
    return HealthResponse(status="ok")


@app.post(
    "/analyze",
    response_model=AnalyzeResponse,
    status_code=status.HTTP_200_OK,
    tags=["Analysis"],
)
@limiter.limit("30/minute")
async def analyze_message(
    request: Request,
    payload: AnalyzeRequest,
) -> AnalyzeResponse:
    """Analyzes a suspicious text message or SMS using deterministic heuristics.

    Applies 12 pattern families, calculates risk score, maps risk tier,
    and returns template-driven natural-language explanations and safety recommendations.
    """
    # 1. Execute deterministic heuristic rules
    flags = run_all_heuristics(payload.message, payload.sender_id)

    # 2. Compute aggregate risk score and tier
    risk_score, label = evaluate_flags(flags)

    # 3. Generate plain-English explanation and actionable guidance
    explanation = generate_explanation(flags, risk_score, label)
    recommended_action = generate_recommended_action(flags, risk_score, label)

    return AnalyzeResponse(
        risk_score=risk_score,
        label=label,
        flags=flags,
        explanation=explanation,
        recommended_action=recommended_action,
    )


# ==============================================================================
# STATIC ASSETS & ROOT ROUTE
# ==============================================================================
STATIC_DIR = Path(__file__).resolve().parent / "static"
if not STATIC_DIR.exists():
    STATIC_DIR = Path.cwd() / "app" / "static"

if STATIC_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


@app.api_route("/", methods=["GET", "HEAD"], response_class=HTMLResponse, include_in_schema=False)
async def serve_index():
    """Serves the ScamShield single-page application."""
    index_file = STATIC_DIR / "index.html"
    if index_file.exists():
        return FileResponse(index_file)
    return HTMLResponse(
        content="""<!DOCTYPE html>
<html lang="en">
<head><title>ScamShield</title></head>
<body><h1>ScamShield Suspicious Message Detector</h1><p>Initializing...</p></body>
</html>""",
        status_code=200,
    )


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app.main:app", host=HOST, port=PORT, reload=False)
