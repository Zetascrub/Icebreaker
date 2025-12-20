"""
API endpoints for finding operations including bulk operations and workflow management.
"""
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session
from sqlalchemy import func

from icebreaker.db.database import get_db
from icebreaker.db.models import Finding, Scan
from icebreaker.core.ai_service import enhance_finding_with_ai

router = APIRouter()


# Pydantic models
class FindingUpdate(BaseModel):
    """Model for updating a single finding."""
    status: Optional[str] = None
    severity: Optional[str] = None
    assigned_to: Optional[str] = None
    notes: Optional[str] = None
    false_positive: Optional[bool] = None
    tags: Optional[List[str]] = None


class BulkFindingUpdate(BaseModel):
    """Model for bulk updating findings."""
    finding_ids: List[int]
    status: Optional[str] = None
    severity: Optional[str] = None
    assigned_to: Optional[str] = None
    tags_add: Optional[List[str]] = None  # Tags to add
    tags_remove: Optional[List[str]] = None  # Tags to remove
    false_positive: Optional[bool] = None


class MergeFindingsRequest(BaseModel):
    """Model for merging duplicate findings."""
    finding_ids: List[int]  # IDs of findings to merge
    keep_finding_id: int  # ID of the finding to keep
    merge_notes: bool = True  # Whether to merge notes from all findings


class FindingSimilarity(BaseModel):
    """Model for finding similarity response."""
    finding_id: int
    title: str
    severity: str
    target: str
    port: Optional[int]
    scan_id: int
    similarity_score: float
    similarity_reasons: List[str]


# API Endpoints

@router.get("/findings")
async def list_all_findings(
    severity: Optional[str] = None,
    status: Optional[str] = None,
    scan_id: Optional[int] = None,
    target: Optional[str] = None,
    exclude_false_positives: bool = False,
    only_false_positives: bool = False,
    limit: Optional[int] = None,
    offset: int = 0,
    db: Session = Depends(get_db)
):
    """List all findings across all scans with optional filtering."""
    query = db.query(Finding)

    # Apply filters
    if severity:
        query = query.filter(Finding.severity == severity.upper())

    if status:
        query = query.filter(Finding.status == status)

    if scan_id:
        query = query.filter(Finding.scan_id == scan_id)

    if target:
        query = query.filter(Finding.target.like(f"%{target}%"))

    if exclude_false_positives:
        query = query.filter(Finding.false_positive != True)

    if only_false_positives:
        query = query.filter(Finding.false_positive == True)

    # Order by most recent first
    query = query.order_by(Finding.first_seen.desc())

    # Apply pagination
    if limit:
        query = query.limit(limit)

    if offset:
        query = query.offset(offset)

    findings = query.all()

    # Convert to dictionaries with scan info
    result = []
    for finding in findings:
        scan = db.query(Scan).filter(Scan.id == finding.scan_id).first()
        result.append({
            "id": finding.id,
            "finding_id": finding.finding_id,
            "title": finding.title,
            "severity": finding.severity,
            "status": finding.status,
            "target": finding.target,
            "port": finding.port,
            "recommendation": finding.recommendation,
            "false_positive": finding.false_positive,
            "assigned_to": finding.assigned_to,
            "notes": finding.notes,
            "first_seen": finding.first_seen.isoformat() if finding.first_seen else None,
            "last_seen": finding.last_seen.isoformat() if finding.last_seen else None,
            "tags": finding.tags,
            "confidence": finding.confidence,
            "risk_score": finding.risk_score,
            "details": finding.details,
            "scan_id": finding.scan_id,
            "scan_name": scan.name if scan else None
            # "template_id": removed - finding templates no longer exist
        })

    return result


@router.put("/findings/{finding_id}")
async def update_finding(
    finding_id: int,
    update: FindingUpdate,
    db: Session = Depends(get_db)
):
    """Update a single finding."""
    finding = db.query(Finding).filter(Finding.id == finding_id).first()
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    # Update fields if provided
    if update.status is not None:
        finding.status = update.status
    if update.severity is not None:
        finding.severity = update.severity
    if update.assigned_to is not None:
        finding.assigned_to = update.assigned_to
    if update.notes is not None:
        finding.notes = update.notes
    if update.false_positive is not None:
        finding.false_positive = update.false_positive
    if update.tags is not None:
        finding.tags = update.tags

    db.commit()
    db.refresh(finding)

    return {
        "id": finding.id,
        "status": finding.status,
        "severity": finding.severity,
        "assigned_to": finding.assigned_to,
        "false_positive": finding.false_positive,
        "tags": finding.tags
    }


@router.post("/findings/bulk-update")
async def bulk_update_findings(
    update: BulkFindingUpdate,
    db: Session = Depends(get_db)
):
    """Bulk update multiple findings."""
    if not update.finding_ids:
        raise HTTPException(status_code=400, detail="No finding IDs provided")

    # Fetch all findings
    findings = db.query(Finding).filter(Finding.id.in_(update.finding_ids)).all()

    if not findings:
        raise HTTPException(status_code=404, detail="No findings found")

    updated_count = 0
    for finding in findings:
        # Update fields if provided
        if update.status is not None:
            finding.status = update.status
        if update.severity is not None:
            finding.severity = update.severity
        if update.assigned_to is not None:
            finding.assigned_to = update.assigned_to
        if update.false_positive is not None:
            finding.false_positive = update.false_positive

        # Handle tag additions and removals
        if update.tags_add or update.tags_remove:
            current_tags = set(finding.tags or [])

            if update.tags_add:
                current_tags.update(update.tags_add)

            if update.tags_remove:
                current_tags.difference_update(update.tags_remove)

            finding.tags = list(current_tags)

        updated_count += 1

    db.commit()

    return {
        "updated_count": updated_count,
        "finding_ids": update.finding_ids
    }


@router.post("/findings/merge")
async def merge_findings(
    request: MergeFindingsRequest,
    db: Session = Depends(get_db)
):
    """Merge duplicate findings into one."""
    if len(request.finding_ids) < 2:
        raise HTTPException(status_code=400, detail="At least 2 findings required for merging")

    if request.keep_finding_id not in request.finding_ids:
        raise HTTPException(status_code=400, detail="keep_finding_id must be one of the finding_ids")

    # Fetch all findings
    findings = db.query(Finding).filter(Finding.id.in_(request.finding_ids)).all()

    if len(findings) != len(request.finding_ids):
        raise HTTPException(status_code=404, detail="One or more findings not found")

    # Get the finding to keep
    keep_finding = next((f for f in findings if f.id == request.keep_finding_id), None)
    if not keep_finding:
        raise HTTPException(status_code=404, detail="Finding to keep not found")

    # Merge notes if requested
    if request.merge_notes:
        merged_notes = []
        if keep_finding.notes:
            merged_notes.append(keep_finding.notes)

        for finding in findings:
            if finding.id != request.keep_finding_id and finding.notes:
                merged_notes.append(f"[Merged from finding #{finding.id}]: {finding.notes}")

        if merged_notes:
            keep_finding.notes = "\n\n".join(merged_notes)

    # Merge tags
    all_tags = set(keep_finding.tags or [])
    for finding in findings:
        if finding.id != request.keep_finding_id:
            all_tags.update(finding.tags or [])
    keep_finding.tags = list(all_tags)

    # Take the highest severity
    severity_order = {'critical': 5, 'high': 4, 'medium': 3, 'low': 2, 'info': 1}
    highest_severity = max(
        (finding.severity for finding in findings),
        key=lambda s: severity_order.get(s.lower(), 0)
    )
    keep_finding.severity = highest_severity

    # Delete other findings
    finding_ids_to_delete = [f.id for f in findings if f.id != request.keep_finding_id]
    db.query(Finding).filter(Finding.id.in_(finding_ids_to_delete)).delete(synchronize_session=False)

    db.commit()
    db.refresh(keep_finding)

    return {
        "kept_finding_id": keep_finding.id,
        "deleted_finding_ids": finding_ids_to_delete,
        "merged_finding": {
            "id": keep_finding.id,
            "title": keep_finding.title,
            "severity": keep_finding.severity,
            "tags": keep_finding.tags,
            "notes": keep_finding.notes
        }
    }


@router.get("/findings/duplicates/{scan_id}")
async def find_duplicate_findings(
    scan_id: int,
    similarity_threshold: float = 0.8,
    db: Session = Depends(get_db)
):
    """Find potential duplicate findings in a scan."""
    # Verify scan exists
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    # Get all findings for the scan
    findings = db.query(Finding).filter(Finding.scan_id == scan_id).all()

    # Group findings by similar characteristics
    duplicates = []
    processed_ids = set()

    for i, finding1 in enumerate(findings):
        if finding1.id in processed_ids:
            continue

        similar_group = []

        for finding2 in findings[i+1:]:
            if finding2.id in processed_ids:
                continue

            # Calculate similarity
            similarity_reasons = []
            score = 0.0

            # Same title (50% weight)
            if finding1.title.lower().strip() == finding2.title.lower().strip():
                score += 0.5
                similarity_reasons.append("Identical title")

            # Same target and port (30% weight)
            if finding1.target == finding2.target and finding1.port == finding2.port:
                score += 0.3
                similarity_reasons.append("Same target and port")

            # Same severity (10% weight)
            if finding1.severity == finding2.severity:
                score += 0.1
                similarity_reasons.append("Same severity")

            # Similar finding_id prefix (10% weight)
            if finding1.finding_id.split('-')[0] == finding2.finding_id.split('-')[0]:
                score += 0.1
                similarity_reasons.append("Similar finding ID")

            # If similarity is above threshold, group them
            if score >= similarity_threshold:
                if not similar_group:
                    similar_group.append({
                        "finding_id": finding1.id,
                        "title": finding1.title,
                        "severity": finding1.severity,
                        "target": finding1.target,
                        "port": finding1.port,
                        "scan_id": finding1.scan_id,
                        "similarity_score": 1.0,
                        "similarity_reasons": ["Original finding"]
                    })
                    processed_ids.add(finding1.id)

                similar_group.append({
                    "finding_id": finding2.id,
                    "title": finding2.title,
                    "severity": finding2.severity,
                    "target": finding2.target,
                    "port": finding2.port,
                    "scan_id": finding2.scan_id,
                    "similarity_score": round(score, 2),
                    "similarity_reasons": similarity_reasons
                })
                processed_ids.add(finding2.id)

        if similar_group:
            duplicates.append({
                "group_id": len(duplicates) + 1,
                "findings": similar_group,
                "suggested_action": "Merge these findings"
            })

    return {
        "scan_id": scan_id,
        "total_findings": len(findings),
        "duplicate_groups": duplicates,
        "groups_found": len(duplicates)
    }


@router.get("/findings/status-summary/{scan_id}")
async def get_finding_status_summary(
    scan_id: int,
    db: Session = Depends(get_db)
):
    """Get summary of finding statuses for a scan."""
    # Verify scan exists
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    # Get status counts
    status_counts = db.query(
        Finding.status,
        func.count(Finding.id).label('count')
    ).filter(
        Finding.scan_id == scan_id
    ).group_by(Finding.status).all()

    # Get severity counts
    severity_counts = db.query(
        Finding.severity,
        func.count(Finding.id).label('count')
    ).filter(
        Finding.scan_id == scan_id
    ).group_by(Finding.severity).all()

    # Get false positive count
    false_positive_count = db.query(func.count(Finding.id)).filter(
        Finding.scan_id == scan_id,
        Finding.false_positive == True
    ).scalar()

    return {
        "scan_id": scan_id,
        "status_breakdown": [{"status": s, "count": c} for s, c in status_counts],
        "severity_breakdown": [{"severity": s, "count": c} for s, c in severity_counts],
        "false_positive_count": false_positive_count,
        "total_findings": sum(c for _, c in status_counts)
    }


class EnhanceFindingRequest(BaseModel):
    """Model for AI finding enhancement request."""
    include_raw_output: bool = True


@router.post("/findings/{finding_id}/enhance")
async def enhance_finding(
    finding_id: int,
    request: EnhanceFindingRequest,
    db: Session = Depends(get_db)
):
    """
    Enhance a finding using AI to generate professional descriptions,
    impact statements, and remediation steps.
    """
    # Get the finding
    finding = db.query(Finding).filter(Finding.id == finding_id).first()
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    # Prepare raw output
    raw_output = None
    if request.include_raw_output and finding.details:
        # Extract raw output from details if available
        raw_output = finding.details.get("raw_output") or finding.details.get("output") or str(finding.details)

    try:
        # Call AI service to enhance the finding
        enhanced = await enhance_finding_with_ai(
            db=db,
            title=finding.title,
            description=finding.description or finding.title,
            severity=finding.severity,
            target=finding.target,
            port=finding.port,
            raw_output=raw_output
        )

        # Update the finding with enhanced content
        finding.description = enhanced.get("description") or finding.description

        # Store impact and recommendation in details
        if not finding.details:
            finding.details = {}

        finding.details["ai_enhanced"] = True
        finding.details["impact"] = enhanced.get("impact", "")
        finding.details["recommendation"] = enhanced.get("recommendation", "")

        db.commit()
        db.refresh(finding)

        return {
            "finding_id": finding.id,
            "enhanced": True,
            "description": finding.description,
            "impact": enhanced.get("impact", ""),
            "recommendation": enhanced.get("recommendation", "")
        }

    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"AI enhancement failed: {str(e)}")
