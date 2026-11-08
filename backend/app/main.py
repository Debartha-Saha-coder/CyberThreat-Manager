"""
Hackmetrix — Cyber Threat Intelligence Platform
FastAPI application entry point.
"""

from __future__ import annotations

import logging

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

from app.config import get_settings
from app.database.connection import create_tables
from app.api.routes import auth, scans, community, dashboard

settings = get_settings()

# ------------------------------------------------------------------ #
# Logging
# ------------------------------------------------------------------ #
logging.basicConfig(
    level=logging.DEBUG if settings.debug else logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s — %(message)s",
)
logger = logging.getLogger(__name__)

# ------------------------------------------------------------------ #
# Rate limiter
# ------------------------------------------------------------------ #
limiter = Limiter(key_func=get_remote_address)

# ------------------------------------------------------------------ #
# Application
# ------------------------------------------------------------------ #
app = FastAPI(
    title="Hackmetrix — Cyber Threat Intelligence Platform",
    description=(
        "A unified, modular cybersecurity platform that detects phishing websites, "
        "malicious URLs, suspicious certificates, and web security weaknesses through "
        "four independent analysis engines and collaborative threat intelligence."
    ),
    version="1.0.0",
    docs_url="/api/docs",
    redoc_url="/api/redoc",
    openapi_url="/api/openapi.json",
)

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# ------------------------------------------------------------------ #
# CORS
# ------------------------------------------------------------------ #
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ------------------------------------------------------------------ #
# Routes
# ------------------------------------------------------------------ #
API_PREFIX = "/api/v1"

app.include_router(auth.router, prefix=API_PREFIX)
app.include_router(scans.router, prefix=API_PREFIX)
app.include_router(community.router, prefix=API_PREFIX)
app.include_router(dashboard.router, prefix=API_PREFIX)

# ------------------------------------------------------------------ #
# Startup
# ------------------------------------------------------------------ #
from contextlib import asynccontextmanager

@asynccontextmanager
async def lifespan(application):  # noqa: ANN001
    logger.info("Hackmetrix starting up...")
    create_tables()

    from app.database.connection import SessionLocal
    from app.services.auth_service import ensure_admin_exists
    db = SessionLocal()
    try:
        ensure_admin_exists(db)
        from app.services.seed_data import seed_threat_campaigns, seed_community_reports
        seeded = seed_threat_campaigns(db)
        if seeded:
            logger.info("Seeded %d threat campaign records.", seeded)
        seeded_reports = seed_community_reports(db)
        if seeded_reports:
            logger.info("Seeded %d community report records.", seeded_reports)
    except Exception as exc:
        logger.warning("Database bootstrap failed: %s", exc)
    finally:
        db.close()

    logger.info("Database ready. Admin account and campaign data ensured.")
    yield
    logger.info("Hackmetrix shutting down.")

app.router.lifespan_context = lifespan


@app.get("/api/health")
def health_check():
    return {"status": "ok", "service": "hackmetrix"}


@app.get("/")
def root():
    return {
        "service": "Hackmetrix Cyber Threat Intelligence Platform",
        "version": "1.0.0",
        "docs": "/api/docs",
    }
