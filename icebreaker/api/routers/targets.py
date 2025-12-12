"""
Targets API router - Manage target lists.
"""
from __future__ import annotations
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from typing import List

from icebreaker.db.database import get_db
from icebreaker.db.models import Target

router = APIRouter()


@router.get("/targets")
async def list_targets(db: Session = Depends(get_db)):
    """Get all unique targets across all scans."""
    # Get distinct targets
    targets = db.query(Target.address).distinct().all()
    return [{"address": t[0]} for t in targets]
