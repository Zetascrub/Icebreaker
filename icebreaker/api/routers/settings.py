"""
Settings API router - Manage scan profiles and settings.
"""
from __future__ import annotations
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from typing import List
from pydantic import BaseModel

from icebreaker.db.database import get_db
from icebreaker.db.models import ScanProfile

router = APIRouter()


class ScanProfileCreate(BaseModel):
    """Request model for creating a scan profile."""
    name: str
    description: str | None = None
    config: dict
    is_default: bool = False


class ScanProfileResponse(BaseModel):
    """Response model for scan profile."""
    id: int
    name: str
    description: str | None
    config: dict
    is_default: bool

    class Config:
        from_attributes = True


@router.get("/profiles", response_model=List[ScanProfileResponse])
async def list_profiles(db: Session = Depends(get_db)):
    """Get all scan profiles."""
    profiles = db.query(ScanProfile).all()
    return profiles


@router.post("/profiles", response_model=ScanProfileResponse)
async def create_profile(profile: ScanProfileCreate, db: Session = Depends(get_db)):
    """Create a new scan profile."""
    # Check if name already exists
    existing = db.query(ScanProfile).filter(ScanProfile.name == profile.name).first()
    if existing:
        raise HTTPException(status_code=400, detail="Profile with this name already exists")

    db_profile = ScanProfile(**profile.dict())
    db.add(db_profile)
    db.commit()
    db.refresh(db_profile)

    return db_profile


@router.delete("/profiles/{profile_id}")
async def delete_profile(profile_id: int, db: Session = Depends(get_db)):
    """Delete a scan profile."""
    profile = db.query(ScanProfile).filter(ScanProfile.id == profile_id).first()
    if not profile:
        raise HTTPException(status_code=404, detail="Profile not found")

    db.delete(profile)
    db.commit()

    return {"message": "Profile deleted successfully"}
