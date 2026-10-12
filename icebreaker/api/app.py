"""
FastAPI application for Icebreaker web interface.
"""
from __future__ import annotations

import logging
import os
import secrets
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address
from sqlalchemy.orm import Session
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response

from icebreaker.api.csrf import CSRFMiddleware, get_csrf_token
from icebreaker.api.routers import (
    analytics, exports, findings, plugins, projects,
    reports, scans, schedules, screenshots, settings, targets,
)
from icebreaker.api.websocket import manager
from icebreaker.db.database import engine, get_db, init_db
from icebreaker.db.models import Scan
from icebreaker.scheduler.service import get_scheduler

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Lifespan — startup and graceful shutdown
# ---------------------------------------------------------------------------

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Manage application lifecycle: initialise resources on startup, clean up on shutdown."""
    # ---- Startup ----------------------------------------------------------
    logger.info("Icebreaker starting up…")

    init_db()
    logger.info("Database initialised")

    try:
        get_scheduler()
        logger.info("Scheduler started")
    except Exception as exc:
        logger.warning("Scheduler init failed (scheduled scans unavailable): %s", exc)

    yield  # Application runs

    # ---- Shutdown ---------------------------------------------------------
    logger.info("Icebreaker shutting down…")

    try:
        get_scheduler().shutdown()
        logger.info("Scheduler stopped")
    except Exception as exc:
        logger.warning("Scheduler shutdown error: %s", exc)

    try:
        engine.dispose()
        logger.info("Database connections closed")
    except Exception as exc:
        logger.warning("Database dispose error: %s", exc)

    logger.info("Icebreaker shut down cleanly")


# ---------------------------------------------------------------------------
# App creation
# ---------------------------------------------------------------------------

limiter = Limiter(key_func=get_remote_address)

app = FastAPI(
    title="Icebreaker",
    description="First-strike recon scanner with AI-powered analysis",
    version="0.2.0",
    lifespan=lifespan,
)

# Rate limiting
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# ---------------------------------------------------------------------------
# Middleware
# ---------------------------------------------------------------------------

class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "SAMEORIGIN"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' https://cdn.tailwindcss.com "
            "https://cdn.jsdelivr.net https://unpkg.com; "
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data:; "
            "font-src 'self' data:;"
        )
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
        return response


app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(GZipMiddleware, minimum_size=1000)

csrf_secret = os.getenv("CSRF_SECRET_KEY") or secrets.token_urlsafe(32)
app.state.csrf_secret = csrf_secret

csrf_exempt_paths = ["/api/", "/health", "/docs", "/openapi.json"]
app.add_middleware(CSRFMiddleware, secret_key=csrf_secret, exempt_paths=csrf_exempt_paths)

cors_origins = os.getenv("CORS_ORIGINS", "http://localhost:8000,http://127.0.0.1:8000").split(",")
app.add_middleware(
    CORSMiddleware,
    allow_origins=cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------------------------------------------------------------------------
# Static files & templates
# ---------------------------------------------------------------------------

static_path = Path(__file__).parent.parent / "web" / "static"
static_path.mkdir(parents=True, exist_ok=True)
app.mount("/static", StaticFiles(directory=str(static_path)), name="static")

templates_path = Path(__file__).parent.parent / "web" / "templates"
templates_path.mkdir(parents=True, exist_ok=True)
templates = Jinja2Templates(directory=str(templates_path))
templates.env.globals["get_csrf_token"] = get_csrf_token

# ---------------------------------------------------------------------------
# Routers
# ---------------------------------------------------------------------------

app.include_router(scans.router,       prefix="/api", tags=["scans"])
app.include_router(targets.router,     prefix="/api", tags=["targets"])
app.include_router(settings.router,    prefix="/api", tags=["settings"])
app.include_router(analytics.router,   prefix="/api", tags=["analytics"])
app.include_router(reports.router,     prefix="/api", tags=["reports"])
app.include_router(exports.router,     prefix="/api", tags=["exports"])
app.include_router(schedules.router,   prefix="/api", tags=["schedules"])
app.include_router(findings.router,    prefix="/api", tags=["findings"])
app.include_router(screenshots.router, prefix="/api", tags=["screenshots"])
app.include_router(plugins.router,     prefix="/api", tags=["plugins"])
app.include_router(projects.router,    prefix="/api", tags=["projects"])

# ---------------------------------------------------------------------------
# HTTP routes
# ---------------------------------------------------------------------------

@app.get("/health")
async def health_check():
    """Health check endpoint."""
    return {"status": "ok", "version": "0.2.0", "service": "icebreaker"}


@app.get("/", response_class=HTMLResponse)
async def home(request: Request):
    return templates.TemplateResponse("dashboard.html", {"request": request})


@app.get("/scans", response_class=HTMLResponse)
async def scans_page(request: Request):
    return templates.TemplateResponse("scans.html", {"request": request})


@app.get("/scans/new", response_class=HTMLResponse)
async def new_scan_page(request: Request):
    return templates.TemplateResponse("new_scan.html", {"request": request})


@app.get("/scans/{scan_id}", response_class=HTMLResponse)
async def scan_detail_page(request: Request, scan_id: int):
    return templates.TemplateResponse("scan_detail.html", {"request": request, "scan_id": scan_id})


@app.get("/scans/{scan_id}/screenshots", response_class=HTMLResponse)
async def screenshots_page(request: Request, scan_id: int):
    return templates.TemplateResponse("screenshots.html", {"request": request, "scan_id": scan_id})


@app.get("/settings", response_class=HTMLResponse)
async def settings_page(request: Request):
    return templates.TemplateResponse("settings.html", {"request": request})


@app.get("/plugins", response_class=HTMLResponse)
async def plugins_page(request: Request):
    return templates.TemplateResponse("plugins.html", {"request": request})


@app.get("/projects", response_class=HTMLResponse)
async def projects_page(request: Request):
    return templates.TemplateResponse("projects.html", {"request": request})


@app.get("/projects/{project_id}", response_class=HTMLResponse)
async def project_detail_page(request: Request, project_id: int):
    return templates.TemplateResponse("project_detail.html", {"request": request, "project_id": project_id})


@app.get("/network-map", response_class=HTMLResponse)
async def network_map_page(request: Request):
    return templates.TemplateResponse("network_map.html", {"request": request})


@app.get("/schedules", response_class=HTMLResponse)
async def schedules_page(request: Request):
    return templates.TemplateResponse("schedules.html", {"request": request})


# ---------------------------------------------------------------------------
# WebSocket routes
# ---------------------------------------------------------------------------

@app.websocket("/ws/scans/{scan_id}")
async def websocket_scan_updates(websocket: WebSocket, scan_id: int):
    """Real-time scan progress updates."""
    await manager.connect(websocket, scan_id)
    try:
        db = next(get_db())
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if scan:
            await websocket.send_json({
                "type": "scan_status",
                "data": {
                    "id": scan.id,
                    "status": scan.status.value,
                    "services_found": scan.services_found,
                    "findings_count": scan.findings_count,
                },
            })
        while True:
            await websocket.receive_text()
            await websocket.send_json({"type": "ping", "data": "pong"})
    except WebSocketDisconnect:
        manager.disconnect(websocket, scan_id)


@app.websocket("/ws/dashboard")
async def websocket_dashboard(websocket: WebSocket):
    """Dashboard keepalive WebSocket."""
    await websocket.accept()
    try:
        while True:
            await websocket.receive_text()
            await websocket.send_json({"type": "ping", "data": "pong"})
    except WebSocketDisconnect:
        pass


# ---------------------------------------------------------------------------
# Entry point (used by icebreaker-web command)
# ---------------------------------------------------------------------------

def main():
    """Entry point for the icebreaker-web CLI command."""
    import uvicorn

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(name)s %(levelname)s %(message)s",
    )

    print("Starting Icebreaker Web Interface")
    print("  Dashboard:  http://localhost:8000")
    print("  API docs:   http://localhost:8000/docs")
    print("  Stop with:  Ctrl+C")

    uvicorn.run(
        app,
        host="0.0.0.0",
        port=8000,
        log_level="info",
        # Allow uvicorn to handle SIGTERM/SIGINT gracefully
        # and give lifespan a chance to clean up
        timeout_graceful_shutdown=30,
    )


if __name__ == "__main__":
    main()
