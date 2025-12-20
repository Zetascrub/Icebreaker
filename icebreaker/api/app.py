"""
FastAPI application for Icebreaker web interface.
"""
from __future__ import annotations
import os
from fastapi import FastAPI, Request, WebSocket, WebSocketDisconnect
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.responses import HTMLResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response
from pathlib import Path
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

from icebreaker.api.routers import scans, targets, settings, import_templates, analytics, reports, exports, schedules, findings, screenshots, plugins, projects
from icebreaker.api.websocket import manager
from icebreaker.api.csrf import CSRFMiddleware, get_csrf_token
from icebreaker.db.database import init_db, get_db
from icebreaker.db.models import Scan
from icebreaker.scheduler.service import get_scheduler
from sqlalchemy.orm import Session
import secrets

# Initialize rate limiter
limiter = Limiter(key_func=get_remote_address)

# Create FastAPI app
app = FastAPI(
    title="Icebreaker",
    description="First-strike recon scanner with AI-powered analysis",
    version="0.2.0",
)

# Add rate limiter to app state
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# Generate or load CSRF secret key
csrf_secret = os.getenv("CSRF_SECRET_KEY")
if not csrf_secret:
    # Generate a secret key for CSRF protection
    # In production, this should be set via environment variable
    csrf_secret = secrets.token_urlsafe(32)
app.state.csrf_secret = csrf_secret

# Security Headers Middleware
class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        # Add security headers
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "SAMEORIGIN"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        response.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.tailwindcss.com https://cdn.jsdelivr.net https://unpkg.com; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self' data:;"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
        return response

# Add middleware
app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(GZipMiddleware, minimum_size=1000)

# Add CSRF protection (exempt API endpoints that use tokens, only protect forms)
# Exempt paths: API endpoints that use other authentication mechanisms
csrf_exempt_paths = [
    "/api/",  # API endpoints use other auth mechanisms (JWT in future)
    "/health",  # Health checks
    "/docs",  # OpenAPI docs
    "/openapi.json",  # OpenAPI spec
]
app.add_middleware(CSRFMiddleware, secret_key=csrf_secret, exempt_paths=csrf_exempt_paths)

# CORS configuration
cors_origins = os.getenv("CORS_ORIGINS", "http://localhost:8000,http://127.0.0.1:8000").split(",")
app.add_middleware(
    CORSMiddleware,
    allow_origins=cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize database
init_db()

# Initialize scheduler (loads schedules from database)
try:
    get_scheduler()
except Exception as e:
    print(f"Warning: Failed to initialize scheduler: {e}")

# Mount static files
static_path = Path(__file__).parent.parent / "web" / "static"
static_path.mkdir(parents=True, exist_ok=True)
app.mount("/static", StaticFiles(directory=str(static_path)), name="static")

# Set up templates
templates_path = Path(__file__).parent.parent / "web" / "templates"
templates_path.mkdir(parents=True, exist_ok=True)
templates = Jinja2Templates(directory=str(templates_path))

# Add global template context
templates.env.globals["get_csrf_token"] = get_csrf_token

# Include routers
app.include_router(scans.router, prefix="/api", tags=["scans"])
app.include_router(targets.router, prefix="/api", tags=["targets"])
app.include_router(settings.router, prefix="/api", tags=["settings"])
app.include_router(import_templates.router, prefix="/api", tags=["import"])
app.include_router(analytics.router, prefix="/api", tags=["analytics"])
app.include_router(reports.router, prefix="/api", tags=["reports"])
app.include_router(exports.router, prefix="/api", tags=["exports"])
app.include_router(schedules.router, prefix="/api", tags=["schedules"])
app.include_router(findings.router, prefix="/api", tags=["findings"])
app.include_router(screenshots.router, prefix="/api", tags=["screenshots"])
app.include_router(plugins.router, prefix="/api", tags=["plugins"])
app.include_router(projects.router, prefix="/api", tags=["projects"])


@app.get("/health")
async def health_check():
    """Health check endpoint for monitoring and load balancers."""
    return {
        "status": "ok",
        "version": "0.2.0",
        "service": "icebreaker"
    }


@app.get("/", response_class=HTMLResponse)
async def home(request: Request):
    """Home page - Dashboard."""
    return templates.TemplateResponse("dashboard.html", {"request": request})


@app.get("/scans", response_class=HTMLResponse)
async def scans_page(request: Request):
    """Scans history page."""
    return templates.TemplateResponse("scans.html", {"request": request})


@app.get("/scans/new", response_class=HTMLResponse)
async def new_scan_page(request: Request):
    """New scan creation page."""
    return templates.TemplateResponse("new_scan.html", {"request": request})


@app.get("/scans/{scan_id}", response_class=HTMLResponse)
async def scan_detail_page(request: Request, scan_id: int):
    """Scan detail page."""
    return templates.TemplateResponse("scan_detail.html", {"request": request, "scan_id": scan_id})


@app.get("/scans/{scan_id}/screenshots", response_class=HTMLResponse)
async def screenshots_page(request: Request, scan_id: int):
    """Screenshot gallery page."""
    return templates.TemplateResponse("screenshots.html", {"request": request, "scan_id": scan_id})


@app.get("/settings", response_class=HTMLResponse)
async def settings_page(request: Request):
    """Settings page."""
    return templates.TemplateResponse("settings.html", {"request": request})




@app.get("/plugins", response_class=HTMLResponse)
async def plugins_page(request: Request):
    """Plugin management page."""
    return templates.TemplateResponse("plugins.html", {"request": request})


@app.get("/projects", response_class=HTMLResponse)
async def projects_page(request: Request):
    """Projects management page."""
    return templates.TemplateResponse("projects.html", {"request": request})


@app.get("/projects/{project_id}", response_class=HTMLResponse)
async def project_detail_page(request: Request, project_id: int):
    """Project detail page."""
    return templates.TemplateResponse("project_detail.html", {"request": request, "project_id": project_id})


# Removed - template import feature deprecated
# @app.get("/import", response_class=HTMLResponse)
# async def import_page(request: Request):
#     """Template import page."""
#     return templates.TemplateResponse("import.html", {"request": request})


@app.get("/network-map", response_class=HTMLResponse)
async def network_map_page(request: Request):
    """Network topology visualization page."""
    return templates.TemplateResponse("network_map.html", {"request": request})


@app.get("/schedules", response_class=HTMLResponse)
async def schedules_page(request: Request):
    """Scheduled scans management page."""
    return templates.TemplateResponse("schedules.html", {"request": request})


@app.websocket("/ws/scans/{scan_id}")
async def websocket_scan_updates(websocket: WebSocket, scan_id: int):
    """WebSocket endpoint for real-time scan updates."""
    await manager.connect(websocket, scan_id)
    try:
        # Send initial scan status
        db = next(get_db())
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if scan:
            await websocket.send_json({
                "type": "scan_status",
                "data": {
                    "id": scan.id,
                    "status": scan.status.value,
                    "services_found": scan.services_found,
                    "findings_count": scan.findings_count
                }
            })

        # Keep connection alive and listen for messages
        while True:
            data = await websocket.receive_text()
            # Echo back for keepalive
            await websocket.send_json({"type": "ping", "data": "pong"})
    except WebSocketDisconnect:
        manager.disconnect(websocket, scan_id)


@app.websocket("/ws/dashboard")
async def websocket_dashboard(websocket: WebSocket):
    """WebSocket endpoint for dashboard updates."""
    await websocket.accept()
    try:
        while True:
            data = await websocket.receive_text()
            await websocket.send_json({"type": "ping", "data": "pong"})
    except WebSocketDisconnect:
        pass


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)


def main():
    """Entry point for icebreaker-web command."""
    import uvicorn
    import logging

    # Configure logging - set root logger to INFO level
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )

    # Set specific loggers to INFO
    logging.getLogger("icebreaker").setLevel(logging.INFO)
    logging.getLogger("icebreaker.api.routers.scans").setLevel(logging.INFO)
    logging.getLogger("icebreaker.core.plugin_executor").setLevel(logging.INFO)

    print("🧊 Starting Icebreaker Web Interface...")
    print("📡 API Documentation: http://localhost:8000/docs")
    print("🌐 Dashboard: http://localhost:8000")
    print("🔍 Logging level: INFO (detailed execution logs enabled)")

    uvicorn.run(
        app,
        host="0.0.0.0",
        port=8000,
        log_level="info"
    )
