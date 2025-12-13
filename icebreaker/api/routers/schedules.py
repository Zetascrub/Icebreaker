"""
Schedule management API router - Manage scheduled and recurring scans.
"""
from __future__ import annotations
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from pydantic import BaseModel
from typing import List, Dict, Any, Optional
from datetime import datetime

from icebreaker.db.database import get_db
from icebreaker.db.models import ScanSchedule, ScanProfile
from icebreaker.scheduler.service import get_scheduler

router = APIRouter()


class ScheduleCreate(BaseModel):
    """Request model for creating a schedule."""
    name: str
    description: Optional[str] = None
    schedule_type: str  # cron, interval, once
    schedule_value: str  # cron expression, interval, or datetime
    targets: List[str]
    scan_profile_id: Optional[int] = None
    scan_config: Optional[Dict[str, Any]] = None
    enabled: bool = True


class ScheduleUpdate(BaseModel):
    """Request model for updating a schedule."""
    name: Optional[str] = None
    description: Optional[str] = None
    schedule_type: Optional[str] = None
    schedule_value: Optional[str] = None
    targets: Optional[List[str]] = None
    scan_profile_id: Optional[int] = None
    scan_config: Optional[Dict[str, Any]] = None
    enabled: Optional[bool] = None


@router.get("/schedules")
async def list_schedules(db: Session = Depends(get_db)) -> List[Dict[str, Any]]:
    """List all scan schedules."""
    schedules = db.query(ScanSchedule).order_by(ScanSchedule.created_at.desc()).all()

    scheduler = get_scheduler()

    return [
        {
            "id": s.id,
            "name": s.name,
            "description": s.description,
            "schedule_type": s.schedule_type,
            "schedule_value": s.schedule_value,
            "targets": s.targets,
            "scan_profile_id": s.scan_profile_id,
            "scan_config": s.scan_config,
            "enabled": s.enabled,
            "last_run": s.last_run.isoformat() if s.last_run else None,
            "next_run": s.next_run.isoformat() if s.next_run else None,
            "created_at": s.created_at.isoformat(),
            "updated_at": s.updated_at.isoformat(),
            "job_info": scheduler.get_schedule_info(s.id)
        }
        for s in schedules
    ]


@router.get("/schedules/{schedule_id}")
async def get_schedule(schedule_id: int, db: Session = Depends(get_db)) -> Dict[str, Any]:
    """Get a specific schedule."""
    schedule = db.query(ScanSchedule).filter(ScanSchedule.id == schedule_id).first()
    if not schedule:
        raise HTTPException(status_code=404, detail="Schedule not found")

    scheduler = get_scheduler()

    return {
        "id": schedule.id,
        "name": schedule.name,
        "description": schedule.description,
        "schedule_type": schedule.schedule_type,
        "schedule_value": schedule.schedule_value,
        "targets": schedule.targets,
        "scan_profile_id": schedule.scan_profile_id,
        "scan_config": schedule.scan_config,
        "enabled": schedule.enabled,
        "last_run": schedule.last_run.isoformat() if schedule.last_run else None,
        "next_run": schedule.next_run.isoformat() if schedule.next_run else None,
        "created_at": schedule.created_at.isoformat(),
        "updated_at": schedule.updated_at.isoformat(),
        "job_info": scheduler.get_schedule_info(schedule.id)
    }


@router.post("/schedules")
async def create_schedule(data: ScheduleCreate, db: Session = Depends(get_db)) -> Dict[str, Any]:
    """Create a new scan schedule."""
    # Validate schedule type
    if data.schedule_type not in ['cron', 'interval', 'once']:
        raise HTTPException(status_code=400, detail="Invalid schedule_type. Must be cron, interval, or once")

    # Validate targets
    if not data.targets or len(data.targets) == 0:
        raise HTTPException(status_code=400, detail="At least one target is required")

    # Create schedule
    schedule = ScanSchedule(
        name=data.name,
        description=data.description,
        schedule_type=data.schedule_type,
        schedule_value=data.schedule_value,
        targets=data.targets,
        scan_profile_id=data.scan_profile_id,
        scan_config=data.scan_config or {},
        enabled=data.enabled
    )

    db.add(schedule)
    db.commit()
    db.refresh(schedule)

    # Add to scheduler if enabled
    if schedule.enabled:
        scheduler = get_scheduler()
        scheduler.add_schedule(schedule)

        # Update next_run time
        job_info = scheduler.get_schedule_info(schedule.id)
        if job_info and job_info.get('next_run_time'):
            schedule.next_run = datetime.fromisoformat(job_info['next_run_time'])
            db.commit()

    return {
        "id": schedule.id,
        "name": schedule.name,
        "description": schedule.description,
        "schedule_type": schedule.schedule_type,
        "schedule_value": schedule.schedule_value,
        "targets": schedule.targets,
        "enabled": schedule.enabled,
        "created_at": schedule.created_at.isoformat()
    }


@router.put("/schedules/{schedule_id}")
async def update_schedule(
    schedule_id: int,
    data: ScheduleUpdate,
    db: Session = Depends(get_db)
) -> Dict[str, Any]:
    """Update a scan schedule."""
    schedule = db.query(ScanSchedule).filter(ScanSchedule.id == schedule_id).first()
    if not schedule:
        raise HTTPException(status_code=404, detail="Schedule not found")

    # Track if schedule configuration changed
    schedule_changed = False

    # Update fields
    if data.name is not None:
        schedule.name = data.name
    if data.description is not None:
        schedule.description = data.description
    if data.schedule_type is not None:
        if data.schedule_type not in ['cron', 'interval', 'once']:
            raise HTTPException(status_code=400, detail="Invalid schedule_type")
        schedule.schedule_type = data.schedule_type
        schedule_changed = True
    if data.schedule_value is not None:
        schedule.schedule_value = data.schedule_value
        schedule_changed = True
    if data.targets is not None:
        if len(data.targets) == 0:
            raise HTTPException(status_code=400, detail="At least one target is required")
        schedule.targets = data.targets
    if data.scan_profile_id is not None:
        schedule.scan_profile_id = data.scan_profile_id
    if data.scan_config is not None:
        schedule.scan_config = data.scan_config
    if data.enabled is not None:
        if schedule.enabled != data.enabled:
            schedule_changed = True
        schedule.enabled = data.enabled

    schedule.updated_at = datetime.utcnow()
    db.commit()
    db.refresh(schedule)

    # Update scheduler
    scheduler = get_scheduler()
    if schedule.enabled and schedule_changed:
        scheduler.add_schedule(schedule)
        # Update next_run time
        job_info = scheduler.get_schedule_info(schedule.id)
        if job_info and job_info.get('next_run_time'):
            schedule.next_run = datetime.fromisoformat(job_info['next_run_time'])
            db.commit()
    elif not schedule.enabled:
        scheduler.remove_schedule(schedule.id)

    return {
        "id": schedule.id,
        "name": schedule.name,
        "description": schedule.description,
        "schedule_type": schedule.schedule_type,
        "schedule_value": schedule.schedule_value,
        "targets": schedule.targets,
        "enabled": schedule.enabled,
        "updated_at": schedule.updated_at.isoformat()
    }


@router.delete("/schedules/{schedule_id}")
async def delete_schedule(schedule_id: int, db: Session = Depends(get_db)):
    """Delete a scan schedule."""
    schedule = db.query(ScanSchedule).filter(ScanSchedule.id == schedule_id).first()
    if not schedule:
        raise HTTPException(status_code=404, detail="Schedule not found")

    # Remove from scheduler
    scheduler = get_scheduler()
    scheduler.remove_schedule(schedule_id)

    # Delete from database
    db.delete(schedule)
    db.commit()

    return {"message": f"Schedule {schedule_id} deleted successfully"}


@router.post("/schedules/{schedule_id}/enable")
async def enable_schedule(schedule_id: int, db: Session = Depends(get_db)):
    """Enable a schedule."""
    schedule = db.query(ScanSchedule).filter(ScanSchedule.id == schedule_id).first()
    if not schedule:
        raise HTTPException(status_code=404, detail="Schedule not found")

    if not schedule.enabled:
        schedule.enabled = True
        schedule.updated_at = datetime.utcnow()
        db.commit()

        # Add to scheduler
        scheduler = get_scheduler()
        scheduler.add_schedule(schedule)

        # Update next_run time
        job_info = scheduler.get_schedule_info(schedule.id)
        if job_info and job_info.get('next_run_time'):
            schedule.next_run = datetime.fromisoformat(job_info['next_run_time'])
            db.commit()

    return {"message": "Schedule enabled successfully"}


@router.post("/schedules/{schedule_id}/disable")
async def disable_schedule(schedule_id: int, db: Session = Depends(get_db)):
    """Disable a schedule."""
    schedule = db.query(ScanSchedule).filter(ScanSchedule.id == schedule_id).first()
    if not schedule:
        raise HTTPException(status_code=404, detail="Schedule not found")

    if schedule.enabled:
        schedule.enabled = False
        schedule.updated_at = datetime.utcnow()
        db.commit()

        # Remove from scheduler
        scheduler = get_scheduler()
        scheduler.remove_schedule(schedule_id)

    return {"message": "Schedule disabled successfully"}


@router.post("/schedules/{schedule_id}/trigger")
async def trigger_schedule_now(schedule_id: int, db: Session = Depends(get_db)):
    """Manually trigger a schedule to run now (outside of its normal schedule)."""
    schedule = db.query(ScanSchedule).filter(ScanSchedule.id == schedule_id).first()
    if not schedule:
        raise HTTPException(status_code=404, detail="Schedule not found")

    # Trigger the scan immediately
    scheduler = get_scheduler()
    scheduler._execute_scheduled_scan(schedule_id)

    return {"message": "Schedule triggered successfully"}


# Scan Profiles endpoints
@router.get("/scan-profiles")
async def list_scan_profiles(db: Session = Depends(get_db)) -> List[Dict[str, Any]]:
    """List all scan profiles."""
    profiles = db.query(ScanProfile).order_by(ScanProfile.created_at.desc()).all()

    return [
        {
            "id": p.id,
            "name": p.name,
            "description": p.description,
            "config": p.config,
            "is_default": p.is_default,
            "created_at": p.created_at.isoformat(),
            "updated_at": p.updated_at.isoformat()
        }
        for p in profiles
    ]


@router.post("/scan-profiles")
async def create_scan_profile(
    name: str,
    config: Dict[str, Any],
    description: Optional[str] = None,
    is_default: bool = False,
    db: Session = Depends(get_db)
) -> Dict[str, Any]:
    """Create a new scan profile."""
    # Check if name already exists
    existing = db.query(ScanProfile).filter(ScanProfile.name == name).first()
    if existing:
        raise HTTPException(status_code=400, detail="Profile with this name already exists")

    profile = ScanProfile(
        name=name,
        description=description,
        config=config,
        is_default=is_default
    )

    db.add(profile)
    db.commit()
    db.refresh(profile)

    return {
        "id": profile.id,
        "name": profile.name,
        "description": profile.description,
        "config": profile.config,
        "is_default": profile.is_default,
        "created_at": profile.created_at.isoformat()
    }
