"""
API endpoints for screenshot operations.
"""
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from fastapi.responses import FileResponse
from pydantic import BaseModel
from sqlalchemy.orm import Session
from pathlib import Path

from icebreaker.db.database import get_db
from icebreaker.db.models import Screenshot, Scan, Service
from icebreaker.core.screenshot_service import ScreenshotService

router = APIRouter()


# Pydantic models
class ScreenshotResponse(BaseModel):
    """Model for screenshot response."""
    id: int
    service_id: int
    scan_id: int
    url: str
    screenshot_path: str
    page_title: Optional[str]
    status_code: Optional[int]
    content_type: Optional[str]
    capture_status: str
    error_message: Optional[str]
    captured_at: Optional[str]
    technologies: List[str]

    # Service details
    target: str
    port: int
    service_name: Optional[str]


class CaptureScreenshotsRequest(BaseModel):
    """Model for requesting screenshot capture."""
    service_ids: Optional[List[int]] = None  # If None, capture all HTTP/HTTPS services


# API Endpoints

@router.post("/scans/{scan_id}/screenshots/capture")
async def capture_screenshots(
    scan_id: int,
    request: CaptureScreenshotsRequest,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db)
):
    """
    Trigger screenshot capture for services in a scan.

    If service_ids is provided, only capture those services.
    Otherwise, capture all HTTP/HTTPS services.
    """
    # Verify scan exists
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    # If specific service IDs provided, verify they exist and belong to this scan
    if request.service_ids:
        services = db.query(Service).filter(
            Service.id.in_(request.service_ids),
            Service.scan_id == scan_id
        ).all()

        if len(services) != len(request.service_ids):
            raise HTTPException(status_code=400, detail="Some service IDs not found or don't belong to this scan")

    # Start screenshot capture in background
    background_tasks.add_task(
        _capture_screenshots_background,
        scan_id=scan_id,
        service_ids=request.service_ids
    )

    return {
        "message": "Screenshot capture started",
        "scan_id": scan_id,
        "service_count": len(request.service_ids) if request.service_ids else "all"
    }


def _capture_screenshots_background(scan_id: int, service_ids: Optional[List[int]] = None):
    """Background task for capturing screenshots."""
    from icebreaker.db.database import SessionLocal
    import asyncio

    db = SessionLocal()
    try:
        service = ScreenshotService()

        # Get services to screenshot
        query = db.query(Service).filter(Service.scan_id == scan_id)

        if service_ids:
            query = query.filter(Service.id.in_(service_ids))
        else:
            # Only HTTP/HTTPS services
            query = query.filter(
                Service.name.in_(['http', 'https', 'ssl/http', 'http-proxy', 'https-alt'])
            )

        services = query.all()

        async def capture_all():
            for svc in services:
                # Determine URL scheme
                if svc.name in ['https', 'ssl/http']:
                    scheme = 'https'
                else:
                    scheme = 'http'

                url = f"{scheme}://{svc.target}:{svc.port}"

                await service.capture_screenshot(
                    url=url,
                    service_id=svc.id,
                    scan_id=scan_id,
                    db=db
                )

                # Small delay between captures
                await asyncio.sleep(1)

        asyncio.run(capture_all())

    finally:
        db.close()


@router.get("/scans/{scan_id}/screenshots")
async def get_scan_screenshots(
    scan_id: int,
    status: Optional[str] = None,
    technology: Optional[str] = None,
    db: Session = Depends(get_db)
):
    """
    Get all screenshots for a scan with optional filtering.

    Args:
        scan_id: ID of the scan
        status: Filter by capture status (pending, success, failed)
        technology: Filter by detected technology
    """
    # Verify scan exists
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    # Build query
    query = db.query(Screenshot).filter(Screenshot.scan_id == scan_id)

    if status:
        query = query.filter(Screenshot.capture_status == status)

    screenshots = query.all()

    # Filter by technology if specified
    if technology:
        screenshots = [s for s in screenshots if technology in (s.technologies or [])]

    # Build response with service details
    result = []
    for screenshot in screenshots:
        service = db.query(Service).filter(Service.id == screenshot.service_id).first()

        result.append({
            "id": screenshot.id,
            "service_id": screenshot.service_id,
            "scan_id": screenshot.scan_id,
            "url": screenshot.url,
            "screenshot_path": screenshot.screenshot_path,
            "page_title": screenshot.page_title,
            "status_code": screenshot.status_code,
            "content_type": screenshot.content_type,
            "capture_status": screenshot.capture_status,
            "error_message": screenshot.error_message,
            "captured_at": screenshot.captured_at.isoformat() if screenshot.captured_at else None,
            "technologies": screenshot.technologies or [],
            "target": service.target if service else None,
            "port": service.port if service else None,
            "service_name": service.name if service else None
        })

    return {
        "scan_id": scan_id,
        "total": len(result),
        "screenshots": result
    }


@router.get("/screenshots/{screenshot_id}")
async def get_screenshot(
    screenshot_id: int,
    db: Session = Depends(get_db)
):
    """Get details of a specific screenshot."""
    screenshot = db.query(Screenshot).filter(Screenshot.id == screenshot_id).first()
    if not screenshot:
        raise HTTPException(status_code=404, detail="Screenshot not found")

    service = db.query(Service).filter(Service.id == screenshot.service_id).first()

    return {
        "id": screenshot.id,
        "service_id": screenshot.service_id,
        "scan_id": screenshot.scan_id,
        "url": screenshot.url,
        "screenshot_path": screenshot.screenshot_path,
        "page_title": screenshot.page_title,
        "status_code": screenshot.status_code,
        "content_type": screenshot.content_type,
        "capture_status": screenshot.capture_status,
        "error_message": screenshot.error_message,
        "captured_at": screenshot.captured_at.isoformat() if screenshot.captured_at else None,
        "technologies": screenshot.technologies or [],
        "headers": screenshot.headers or {},
        "target": service.target if service else None,
        "port": service.port if service else None,
        "service_name": service.name if service else None
    }


@router.get("/screenshots/{screenshot_id}/image")
async def get_screenshot_image(
    screenshot_id: int,
    db: Session = Depends(get_db)
):
    """Get the actual screenshot image file."""
    screenshot = db.query(Screenshot).filter(Screenshot.id == screenshot_id).first()
    if not screenshot:
        raise HTTPException(status_code=404, detail="Screenshot not found")

    if screenshot.capture_status != "success":
        raise HTTPException(status_code=404, detail="Screenshot not available")

    screenshot_path = Path(screenshot.screenshot_path)
    if not screenshot_path.exists():
        raise HTTPException(status_code=404, detail="Screenshot file not found")

    return FileResponse(
        path=screenshot_path,
        media_type="image/png",
        filename=f"screenshot_{screenshot_id}.png"
    )


@router.delete("/screenshots/{screenshot_id}")
async def delete_screenshot(
    screenshot_id: int,
    db: Session = Depends(get_db)
):
    """Delete a screenshot and its file."""
    screenshot = db.query(Screenshot).filter(Screenshot.id == screenshot_id).first()
    if not screenshot:
        raise HTTPException(status_code=404, detail="Screenshot not found")

    # Delete file if it exists
    try:
        screenshot_path = Path(screenshot.screenshot_path)
        if screenshot_path.exists():
            screenshot_path.unlink()
    except Exception as e:
        # Log error but continue with database deletion
        pass

    # Delete database record
    db.delete(screenshot)
    db.commit()

    return {"message": "Screenshot deleted successfully"}


@router.get("/scans/{scan_id}/screenshots/summary")
async def get_screenshots_summary(
    scan_id: int,
    db: Session = Depends(get_db)
):
    """Get summary statistics for screenshots in a scan."""
    # Verify scan exists
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    screenshots = db.query(Screenshot).filter(Screenshot.scan_id == scan_id).all()

    # Calculate statistics
    total = len(screenshots)
    success = len([s for s in screenshots if s.capture_status == "success"])
    failed = len([s for s in screenshots if s.capture_status == "failed"])
    pending = len([s for s in screenshots if s.capture_status == "pending"])

    # Get unique technologies
    all_technologies = set()
    for screenshot in screenshots:
        all_technologies.update(screenshot.technologies or [])

    # Get status code distribution
    status_codes = {}
    for screenshot in screenshots:
        if screenshot.status_code:
            code = screenshot.status_code
            status_codes[code] = status_codes.get(code, 0) + 1

    return {
        "scan_id": scan_id,
        "total_screenshots": total,
        "successful": success,
        "failed": failed,
        "pending": pending,
        "technologies": sorted(list(all_technologies)),
        "status_codes": status_codes
    }
