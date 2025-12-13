"""
FastAPI application for Icebreaker web interface.
"""
from __future__ import annotations
from fastapi import FastAPI, Request, WebSocket, WebSocketDisconnect
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.responses import HTMLResponse
from pathlib import Path

from icebreaker.api.routers import scans, targets, settings, finding_templates, import_templates, analytics, reports, exports, schedules
from icebreaker.api.websocket import manager
from icebreaker.db.database import init_db, get_db
from icebreaker.db.models import Scan
from icebreaker.scheduler.service import get_scheduler
from sqlalchemy.orm import Session

# Create FastAPI app
app = FastAPI(
    title="Icebreaker",
    description="First-strike recon scanner with AI-powered analysis",
    version="0.2.0",
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

# Include routers
app.include_router(scans.router, prefix="/api", tags=["scans"])
app.include_router(targets.router, prefix="/api", tags=["targets"])
app.include_router(settings.router, prefix="/api", tags=["settings"])
app.include_router(finding_templates.router, prefix="/api", tags=["finding_templates"])
app.include_router(import_templates.router, prefix="/api", tags=["import"])
app.include_router(analytics.router, prefix="/api", tags=["analytics"])
app.include_router(reports.router, prefix="/api", tags=["reports"])
app.include_router(exports.router, prefix="/api", tags=["exports"])
app.include_router(schedules.router, prefix="/api", tags=["schedules"])


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


@app.get("/settings", response_class=HTMLResponse)
async def settings_page(request: Request):
    """Settings page."""
    return templates.TemplateResponse("settings.html", {"request": request})


@app.get("/finding-templates", response_class=HTMLResponse)
async def finding_templates_page(request: Request):
    """Finding templates management page."""
    return templates.TemplateResponse("finding_templates.html", {"request": request})


@app.get("/import", response_class=HTMLResponse)
async def import_page(request: Request):
    """Template import page."""
    return templates.TemplateResponse("import.html", {"request": request})


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


@app.get("/health")
async def health_check():
    """Health check endpoint."""
    return {"status": "healthy", "version": "0.2.0"}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)


def main():
    """Entry point for icebreaker-web command."""
    import uvicorn
    print("🧊 Starting Icebreaker Web Interface...")
    print("📡 API Documentation: http://localhost:8000/docs")
    print("🌐 Dashboard: http://localhost:8000")
    uvicorn.run(app, host="0.0.0.0", port=8000)
