"""
Finding Templates API router - CRUD operations for finding templates.
"""
from __future__ import annotations
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from sqlalchemy import desc
from typing import List, Optional
from pydantic import BaseModel, Field
from datetime import datetime

from icebreaker.db.database import get_db
from icebreaker.db.models import FindingTemplate

router = APIRouter()


# Pydantic models for API
class FindingTemplateCreate(BaseModel):
    """Request model for creating a finding template."""
    finding_id: str = Field(..., min_length=1, max_length=100)
    title: str = Field(..., min_length=1, max_length=500)
    category: Optional[str] = None
    description: str
    impact: str
    remediation: str
    severity: str = Field(..., pattern="^(CRITICAL|HIGH|MEDIUM|LOW|INFO)$")
    cvss_score: Optional[float] = Field(None, ge=0.0, le=10.0)
    cvss_vector: Optional[str] = None
    cwe_id: Optional[str] = None
    owasp_2021: Optional[str] = None
    pci_dss: Optional[str] = None
    nist_csf: Optional[str] = None
    references: List[str] = []
    enabled: bool = True


class FindingTemplateUpdate(BaseModel):
    """Request model for updating a finding template."""
    title: Optional[str] = None
    category: Optional[str] = None
    description: Optional[str] = None
    impact: Optional[str] = None
    remediation: Optional[str] = None
    severity: Optional[str] = Field(None, pattern="^(CRITICAL|HIGH|MEDIUM|LOW|INFO)$")
    cvss_score: Optional[float] = Field(None, ge=0.0, le=10.0)
    cvss_vector: Optional[str] = None
    cwe_id: Optional[str] = None
    owasp_2021: Optional[str] = None
    pci_dss: Optional[str] = None
    nist_csf: Optional[str] = None
    references: Optional[List[str]] = None
    enabled: Optional[bool] = None


class FindingTemplateResponse(BaseModel):
    """Response model for finding template data."""
    id: int
    finding_id: str
    title: str
    category: Optional[str]
    description: str
    impact: str
    remediation: str
    severity: str
    cvss_score: Optional[float]
    cvss_vector: Optional[str]
    cwe_id: Optional[str]
    owasp_2021: Optional[str]
    pci_dss: Optional[str]
    nist_csf: Optional[str]
    references: List[str]
    enabled: bool
    created_at: datetime
    updated_at: datetime
    created_by: Optional[str]

    class Config:
        from_attributes = True


@router.get("/finding-templates", response_model=List[FindingTemplateResponse])
async def list_finding_templates(
    skip: int = 0,
    limit: int = 100,
    category: Optional[str] = None,
    severity: Optional[str] = None,
    enabled_only: bool = True,
    db: Session = Depends(get_db)
):
    """
    List all finding templates with optional filtering.

    Args:
        skip: Number of templates to skip (pagination)
        limit: Maximum number of templates to return
        category: Filter by category
        severity: Filter by severity
        enabled_only: Only return enabled templates
        db: Database session

    Returns:
        List of finding templates
    """
    query = db.query(FindingTemplate).order_by(FindingTemplate.finding_id)

    if enabled_only:
        query = query.filter(FindingTemplate.enabled == True)

    if category:
        query = query.filter(FindingTemplate.category == category)

    if severity:
        query = query.filter(FindingTemplate.severity == severity.upper())

    templates = query.offset(skip).limit(limit).all()
    return templates


@router.get("/finding-templates/{template_id}", response_model=FindingTemplateResponse)
async def get_finding_template(template_id: int, db: Session = Depends(get_db)):
    """
    Get detailed finding template information.

    Args:
        template_id: Template ID
        db: Database session

    Returns:
        Finding template details
    """
    template = db.query(FindingTemplate).filter(FindingTemplate.id == template_id).first()
    if not template:
        raise HTTPException(status_code=404, detail="Finding template not found")

    return template


@router.post("/finding-templates", response_model=FindingTemplateResponse)
async def create_finding_template(
    template_request: FindingTemplateCreate,
    db: Session = Depends(get_db)
):
    """
    Create a new finding template.

    Args:
        template_request: Template configuration
        db: Database session

    Returns:
        Created template
    """
    # Check if finding_id already exists
    existing = db.query(FindingTemplate).filter(FindingTemplate.finding_id == template_request.finding_id).first()
    if existing:
        raise HTTPException(status_code=400, detail=f"Finding template with ID '{template_request.finding_id}' already exists")

    template = FindingTemplate(
        finding_id=template_request.finding_id,
        title=template_request.title,
        category=template_request.category,
        description=template_request.description,
        impact=template_request.impact,
        remediation=template_request.remediation,
        severity=template_request.severity.upper(),
        cvss_score=template_request.cvss_score,
        cvss_vector=template_request.cvss_vector,
        cwe_id=template_request.cwe_id,
        owasp_2021=template_request.owasp_2021,
        pci_dss=template_request.pci_dss,
        nist_csf=template_request.nist_csf,
        references=template_request.references,
        enabled=template_request.enabled
    )

    db.add(template)
    db.commit()
    db.refresh(template)

    return template


@router.put("/finding-templates/{template_id}", response_model=FindingTemplateResponse)
async def update_finding_template(
    template_id: int,
    template_update: FindingTemplateUpdate,
    db: Session = Depends(get_db)
):
    """
    Update a finding template.

    Args:
        template_id: Template ID
        template_update: Updated template data
        db: Database session

    Returns:
        Updated template
    """
    template = db.query(FindingTemplate).filter(FindingTemplate.id == template_id).first()
    if not template:
        raise HTTPException(status_code=404, detail="Finding template not found")

    # Update fields if provided
    update_data = template_update.dict(exclude_unset=True)
    for field, value in update_data.items():
        if field == "severity" and value:
            value = value.upper()
        setattr(template, field, value)

    template.updated_at = datetime.utcnow()

    db.commit()
    db.refresh(template)

    return template


@router.delete("/finding-templates/{template_id}")
async def delete_finding_template(template_id: int, db: Session = Depends(get_db)):
    """
    Delete a finding template.

    Args:
        template_id: Template ID
        db: Database session

    Returns:
        Success message
    """
    template = db.query(FindingTemplate).filter(FindingTemplate.id == template_id).first()
    if not template:
        raise HTTPException(status_code=404, detail="Finding template not found")

    # Check if template is in use by any findings
    if template.findings:
        raise HTTPException(
            status_code=400,
            detail=f"Cannot delete template: {len(template.findings)} finding(s) are using this template"
        )

    db.delete(template)
    db.commit()

    return {"message": f"Finding template '{template.finding_id}' deleted successfully"}


@router.get("/finding-templates/categories/list")
async def list_categories(db: Session = Depends(get_db)):
    """
    Get list of all unique categories.

    Args:
        db: Database session

    Returns:
        List of categories
    """
    categories = db.query(FindingTemplate.category).distinct().filter(FindingTemplate.category.isnot(None)).all()
    return [cat[0] for cat in categories if cat[0]]
