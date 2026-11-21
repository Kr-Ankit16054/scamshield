"""Vercel Serverless Function entrypoint for ScamShield FastAPI application.

Imports the production FastAPI `app` instance from `app.main`.
Vercel's ASGI runtime automatically discovers the `app` symbol and delegates
HTTP requests routed by vercel.json rewrites.
"""

import sys
from pathlib import Path

# Ensure project root is present in sys.path so 'app' module resolves reliably
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from app.main import app

