"""
FastAPI application for Icebreaker web interface.
"""
from __future__ import annotations
from fastapi import FastAPI, Request
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.responses import HTMLResponse
from pathlib import Path

from icebreaker.api.routers import scans, targets, settings
from icebreaker.db.database import init_db

# Create FastAPI app
app = FastAPI(
    title="Icebreaker",
    description="First-strike recon scanner with AI-powered analysis",
    version="0.2.0",
)

# Initialize database
init_db()

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
