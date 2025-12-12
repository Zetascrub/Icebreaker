"""
Scans API router - CRUD operations for scans.
"""
from __future__ import annotations
from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from sqlalchemy.orm import Session
from sqlalchemy import desc
from typing import List, Optional
from pydantic import BaseModel, Field
from datetime import datetime

from icebreaker.db.database import get_db
from icebreaker.db.models import Scan, Target, Service, Finding, ScanStatus
from icebreaker.core.models import RunContext, Target as CoreTarget
from icebreaker.engine.orchestrator import Orchestrator

router = APIRouter()


# Pydantic models for API
class ScanCreate(BaseModel):
    """Request model for creating a new scan."""
    name: Optional[str] = None
    targets: List[str] = Field(..., min_items=1)
    preset: str = "quick"
    ports: Optional[str] = None
    host_conc: int = 128
    svc_conc: int = 256
    timeout: float = 1.5
    insecure: bool = False
    ai_provider: Optional[str] = None
    ai_model: Optional[str] = None
    ai_base_url: Optional[str] = None


class ScanResponse(BaseModel):
    """Response model for scan data."""
    id: int
    run_id: str
    name: Optional[str]
    status: str
    preset: str
    started_at: datetime
    completed_at: Optional[datetime]
    duration_seconds: Optional[int]
    target_count: int
    services_found: int
    findings_count: int
    settings: dict

    class Config:
        from_attributes = True


class FindingResponse(BaseModel):
    """Response model for finding data."""
    id: int
    finding_id: str
    title: str
    severity: str
    target: str
    port: Optional[int]
    risk_score: Optional[float]
    confidence: float
    false_positive: bool

    class Config:
        from_attributes = True


@router.post("/scans", response_model=ScanResponse)
async def create_scan(
    scan_request: ScanCreate,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db)
):
    """
    Create and start a new scan.

    Args:
        scan_request: Scan configuration
        background_tasks: FastAPI background tasks
        db: Database session

    Returns:
        Created scan object
    """
    # Create scan record
    scan = Scan(
        run_id=f"web-{datetime.utcnow().strftime('%Y%m%dT%H%M%SZ')}",
        name=scan_request.name,
        status=ScanStatus.PENDING,
        preset=scan_request.preset,
        started_at=datetime.utcnow(),
        target_count=len(scan_request.targets),
        settings={
            "ports": scan_request.ports,
            "host_conc": scan_request.host_conc,
            "svc_conc": scan_request.svc_conc,
            "timeout": scan_request.timeout,
            "insecure": scan_request.insecure,
            "ai_provider": scan_request.ai_provider,
            "ai_model": scan_request.ai_model,
            "ai_base_url": scan_request.ai_base_url,
        }
    )

    db.add(scan)
    db.commit()
    db.refresh(scan)

    # Create target records
    for target_addr in scan_request.targets:
        target = Target(scan_id=scan.id, address=target_addr)
        db.add(target)

    db.commit()

    # Queue scan execution
    background_tasks.add_task(execute_scan, scan.id)

    return scan


@router.get("/scans", response_model=List[ScanResponse])
async def list_scans(
    skip: int = 0,
    limit: int = 50,
    status: Optional[str] = None,
    db: Session = Depends(get_db)
):
    """
    List all scans with optional filtering.

    Args:
        skip: Number of scans to skip (pagination)
        limit: Maximum number of scans to return
        status: Filter by status
        db: Database session

    Returns:
        List of scans
    """
    query = db.query(Scan).order_by(desc(Scan.started_at))

    if status:
        query = query.filter(Scan.status == status)

    scans = query.offset(skip).limit(limit).all()
    return scans


@router.get("/scans/{scan_id}", response_model=ScanResponse)
async def get_scan(scan_id: int, db: Session = Depends(get_db)):
    """
    Get detailed scan information.

    Args:
        scan_id: Scan ID
        db: Database session

    Returns:
        Scan object with details
    """
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    return scan


@router.get("/scans/{scan_id}/findings", response_model=List[FindingResponse])
async def get_scan_findings(scan_id: int, db: Session = Depends(get_db)):
    """
    Get all findings for a scan.

    Args:
        scan_id: Scan ID
        db: Database session

    Returns:
        List of findings
    """
    findings = db.query(Finding).filter(Finding.scan_id == scan_id).order_by(desc(Finding.risk_score)).all()
    return findings


@router.delete("/scans/{scan_id}")
async def delete_scan(scan_id: int, db: Session = Depends(get_db)):
    """
    Delete a scan and all its data.

    Args:
        scan_id: Scan ID
        db: Database session

    Returns:
        Success message
    """
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    db.delete(scan)
    db.commit()

    return {"message": "Scan deleted successfully"}


@router.post("/scans/{scan_id}/findings/{finding_id}/false-positive")
async def mark_false_positive(scan_id: int, finding_id: int, db: Session = Depends(get_db)):
    """
    Mark a finding as false positive.

    Args:
        scan_id: Scan ID
        finding_id: Finding ID
        db: Database session

    Returns:
        Updated finding
    """
    finding = db.query(Finding).filter(
        Finding.scan_id == scan_id,
        Finding.id == finding_id
    ).first()

    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    finding.false_positive = not finding.false_positive
    db.commit()
    db.refresh(finding)

    return finding


async def execute_scan(scan_id: int):
    """
    Execute a scan in the background.

    This function runs the actual Icebreaker scan and stores results in the database.

    Args:
        scan_id: Scan ID to execute
    """
    from icebreaker.db.database import SessionLocal

    db = SessionLocal()

    try:
        # Get scan record
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if not scan:
            return

        # Update status to running
        scan.status = ScanStatus.RUNNING
        db.commit()

        # TODO: Implement actual scan execution
        # This will integrate with the existing Icebreaker engine
        # For now, this is a placeholder

        # Mark as completed
        scan.status = ScanStatus.COMPLETED
        scan.completed_at = datetime.utcnow()
        scan.duration_seconds = int((scan.completed_at - scan.started_at).total_seconds())
        db.commit()

    except Exception as e:
        # Mark as failed
        scan.status = ScanStatus.FAILED
        scan.error_message = str(e)
        db.commit()

    finally:
        db.close()
