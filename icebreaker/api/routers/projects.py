"""
Projects API router - CRUD operations for project/workspace management.
"""
from __future__ import annotations
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from sqlalchemy import func
from typing import List, Optional
from pydantic import BaseModel
from datetime import datetime

from icebreaker.db.database import get_db
from icebreaker.db.models import Project, ProjectStatus, Scan, Finding

router = APIRouter()


# Pydantic models
class ProjectCreate(BaseModel):
    """Request model for creating a new project."""
    name: str
    client_name: Optional[str] = None
    description: Optional[str] = None
    engagement_type: Optional[str] = None
    start_date: Optional[datetime] = None
    end_date: Optional[datetime] = None
    scope: Optional[List[str]] = None
    notes: Optional[str] = None
    tags: Optional[List[str]] = None
    created_by: Optional[str] = None


class ProjectUpdate(BaseModel):
    """Request model for updating a project."""
    name: Optional[str] = None
    client_name: Optional[str] = None
    description: Optional[str] = None
    engagement_type: Optional[str] = None
    start_date: Optional[datetime] = None
    end_date: Optional[datetime] = None
    status: Optional[str] = None
    scope: Optional[List[str]] = None
    notes: Optional[str] = None
    tags: Optional[List[str]] = None


@router.get("/projects")
async def list_projects(
    status: Optional[str] = None,
    client_name: Optional[str] = None,
    db: Session = Depends(get_db)
):
    """List all projects with optional filtering."""
    query = db.query(Project)

    if status:
        try:
            project_status = ProjectStatus(status.lower())
            query = query.filter(Project.status == project_status)
        except ValueError:
            raise HTTPException(status_code=400, detail=f"Invalid status: {status}")

    if client_name:
        query = query.filter(Project.client_name.like(f"%{client_name}%"))

    projects = query.order_by(Project.created_at.desc()).all()

    # Calculate real-time statistics for each project
    result = []
    for p in projects:
        # Get scans count
        total_scans = db.query(Scan).filter(Scan.project_id == p.id).count()

        # Get findings counts
        findings = db.query(Finding).join(Scan).filter(Scan.project_id == p.id).all()
        total_findings = len(findings)
        critical_findings = sum(1 for f in findings if f.severity == "CRITICAL")
        high_findings = sum(1 for f in findings if f.severity == "HIGH")

        result.append({
            'id': p.id,
            'name': p.name,
            'client_name': p.client_name,
            'description': p.description,
            'engagement_type': p.engagement_type,
            'start_date': p.start_date.isoformat() if p.start_date else None,
            'end_date': p.end_date.isoformat() if p.end_date else None,
            'status': p.status.value,
            'created_at': p.created_at.isoformat(),
            'updated_at': p.updated_at.isoformat(),
            'created_by': p.created_by,
            'scope': p.scope,
            'notes': p.notes,
            'tags': p.tags,
            'total_scans': total_scans,
            'total_findings': total_findings,
            'critical_findings': critical_findings,
            'high_findings': high_findings
        })

    return result


@router.get("/projects/{project_id}")
async def get_project(project_id: int, db: Session = Depends(get_db)):
    """Get a single project by ID with detailed statistics."""
    project = db.query(Project).filter(Project.id == project_id).first()
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    # Get real-time statistics
    scans = db.query(Scan).filter(Scan.project_id == project_id).all()
    total_scans = len(scans)

    # Get findings count by severity
    findings = db.query(Finding).join(Scan).filter(Scan.project_id == project_id).all()
    total_findings = len(findings)
    critical_findings = sum(1 for f in findings if f.severity == "CRITICAL")
    high_findings = sum(1 for f in findings if f.severity == "HIGH")
    medium_findings = sum(1 for f in findings if f.severity == "MEDIUM")
    low_findings = sum(1 for f in findings if f.severity == "LOW")
    info_findings = sum(1 for f in findings if f.severity == "INFO")

    # Get recent scans
    recent_scans = db.query(Scan).filter(
        Scan.project_id == project_id
    ).order_by(Scan.started_at.desc()).limit(10).all()

    return {
        'id': project.id,
        'name': project.name,
        'client_name': project.client_name,
        'description': project.description,
        'engagement_type': project.engagement_type,
        'start_date': project.start_date.isoformat() if project.start_date else None,
        'end_date': project.end_date.isoformat() if project.end_date else None,
        'status': project.status.value,
        'created_at': project.created_at.isoformat(),
        'updated_at': project.updated_at.isoformat(),
        'created_by': project.created_by,
        'scope': project.scope,
        'notes': project.notes,
        'tags': project.tags,
        'statistics': {
            'total_scans': total_scans,
            'total_findings': total_findings,
            'critical_findings': critical_findings,
            'high_findings': high_findings,
            'medium_findings': medium_findings,
            'low_findings': low_findings,
            'info_findings': info_findings
        },
        'recent_scans': [{
            'id': s.id,
            'name': s.name,
            'run_id': s.run_id,
            'status': s.status.value,
            'started_at': s.started_at.isoformat(),
            'completed_at': s.completed_at.isoformat() if s.completed_at else None,
            'findings_count': s.findings_count
        } for s in recent_scans]
    }


@router.post("/projects")
async def create_project(project: ProjectCreate, db: Session = Depends(get_db)):
    """Create a new project."""
    # Check if project name already exists
    existing = db.query(Project).filter(Project.name == project.name).first()
    if existing:
        raise HTTPException(status_code=400, detail=f"Project with name '{project.name}' already exists")

    # Create project
    new_project = Project(
        name=project.name,
        client_name=project.client_name,
        description=project.description,
        engagement_type=project.engagement_type,
        start_date=project.start_date,
        end_date=project.end_date,
        status=ProjectStatus.ACTIVE,
        created_at=datetime.utcnow(),
        updated_at=datetime.utcnow(),
        created_by=project.created_by,
        scope=project.scope,
        notes=project.notes,
        tags=project.tags,
        total_scans=0,
        total_findings=0,
        critical_findings=0,
        high_findings=0
    )

    db.add(new_project)
    db.commit()
    db.refresh(new_project)

    return {
        'success': True,
        'project_id': new_project.id,
        'message': f"Project '{new_project.name}' created successfully"
    }


@router.put("/projects/{project_id}")
async def update_project(
    project_id: int,
    project: ProjectUpdate,
    db: Session = Depends(get_db)
):
    """Update an existing project."""
    existing = db.query(Project).filter(Project.id == project_id).first()
    if not existing:
        raise HTTPException(status_code=404, detail="Project not found")

    # Update fields if provided
    if project.name is not None:
        # Check for name conflicts
        conflict = db.query(Project).filter(
            Project.name == project.name,
            Project.id != project_id
        ).first()
        if conflict:
            raise HTTPException(status_code=400, detail=f"Project with name '{project.name}' already exists")
        existing.name = project.name

    if project.client_name is not None:
        existing.client_name = project.client_name
    if project.description is not None:
        existing.description = project.description
    if project.engagement_type is not None:
        existing.engagement_type = project.engagement_type
    if project.start_date is not None:
        existing.start_date = project.start_date
    if project.end_date is not None:
        existing.end_date = project.end_date
    if project.status is not None:
        try:
            existing.status = ProjectStatus(project.status.lower())
        except ValueError:
            raise HTTPException(status_code=400, detail=f"Invalid status: {project.status}")
    if project.scope is not None:
        existing.scope = project.scope
    if project.notes is not None:
        existing.notes = project.notes
    if project.tags is not None:
        existing.tags = project.tags

    existing.updated_at = datetime.utcnow()

    db.commit()

    return {
        'success': True,
        'message': f"Project '{existing.name}' updated successfully"
    }


@router.delete("/projects/{project_id}")
async def delete_project(project_id: int, db: Session = Depends(get_db)):
    """Delete a project and all its scans."""
    project = db.query(Project).filter(Project.id == project_id).first()
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    # Check if project has scans
    scan_count = db.query(Scan).filter(Scan.project_id == project_id).count()

    project_name = project.name
    db.delete(project)
    db.commit()

    return {
        'success': True,
        'message': f"Project '{project_name}' deleted successfully (removed {scan_count} scans)"
    }


@router.post("/projects/{project_id}/archive")
async def archive_project(project_id: int, db: Session = Depends(get_db)):
    """Archive a project (change status to archived)."""
    project = db.query(Project).filter(Project.id == project_id).first()
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    project.status = ProjectStatus.ARCHIVED
    project.updated_at = datetime.utcnow()
    db.commit()

    return {
        'success': True,
        'message': f"Project '{project.name}' archived successfully"
    }


@router.post("/projects/{project_id}/activate")
async def activate_project(project_id: int, db: Session = Depends(get_db)):
    """Activate an archived project."""
    project = db.query(Project).filter(Project.id == project_id).first()
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    project.status = ProjectStatus.ACTIVE
    project.updated_at = datetime.utcnow()
    db.commit()

    return {
        'success': True,
        'message': f"Project '{project.name}' activated successfully"
    }


@router.post("/projects/{project_id}/refresh-stats")
async def refresh_project_stats(project_id: int, db: Session = Depends(get_db)):
    """Recalculate and update project statistics."""
    project = db.query(Project).filter(Project.id == project_id).first()
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    # Recalculate statistics
    total_scans = db.query(Scan).filter(Scan.project_id == project_id).count()

    # Get findings counts
    findings = db.query(Finding).join(Scan).filter(Scan.project_id == project_id).all()
    total_findings = len(findings)
    critical_findings = sum(1 for f in findings if f.severity == "CRITICAL")
    high_findings = sum(1 for f in findings if f.severity == "HIGH")

    # Update project
    project.total_scans = total_scans
    project.total_findings = total_findings
    project.critical_findings = critical_findings
    project.high_findings = high_findings
    project.updated_at = datetime.utcnow()

    db.commit()

    return {
        'success': True,
        'message': 'Project statistics refreshed',
        'statistics': {
            'total_scans': total_scans,
            'total_findings': total_findings,
            'critical_findings': critical_findings,
            'high_findings': high_findings
        }
    }
