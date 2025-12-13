"""
Reports API router - Generate and download scan reports.
"""
from __future__ import annotations
from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import HTMLResponse
from sqlalchemy.orm import Session

from icebreaker.db.database import get_db
from icebreaker.reports.generator import ReportGenerator

router = APIRouter()


@router.get("/reports/executive/{scan_id}", response_class=HTMLResponse)
async def get_executive_report(scan_id: int, db: Session = Depends(get_db)) -> str:
    """
    Generate an executive summary report for a scan.

    Args:
        scan_id: Scan ID to generate report for
        db: Database session

    Returns:
        HTML report as string
    """
    try:
        generator = ReportGenerator(db)
        report_html = generator.generate_executive_report(scan_id)
        return report_html
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error generating report: {str(e)}")


@router.get("/reports/technical/{scan_id}", response_class=HTMLResponse)
async def get_technical_report(scan_id: int, db: Session = Depends(get_db)) -> str:
    """
    Generate a detailed technical report for a scan.

    Args:
        scan_id: Scan ID to generate report for
        db: Database session

    Returns:
        HTML report as string
    """
    try:
        generator = ReportGenerator(db)
        report_html = generator.generate_technical_report(scan_id)
        return report_html
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error generating report: {str(e)}")
