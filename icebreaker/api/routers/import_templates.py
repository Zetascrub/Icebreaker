"""
API endpoints for importing finding templates from external sources.
DEPRECATED: Template system has been removed in favor of plugin-based findings.
"""
from fastapi import APIRouter, HTTPException

router = APIRouter()

@router.post("/import/nessus/preview")
async def nessus_preview():
    """Deprecated: Template import system has been removed."""
    raise HTTPException(status_code=410, detail="Template import system has been deprecated. Findings are now generated directly by analyzers.")

@router.post("/import/nessus/confirm/{preview_id}")
async def nessus_confirm(preview_id: str):
    """Deprecated: Template import system has been removed."""
    raise HTTPException(status_code=410, detail="Template import system has been deprecated. Findings are now generated directly by analyzers.")

@router.delete("/import/preview/{preview_id}")
async def delete_preview(preview_id: str):
    """Deprecated: Template import system has been removed."""
    raise HTTPException(status_code=410, detail="Template import system has been deprecated.")

@router.post("/import/nessus")
async def import_nessus():
    """Deprecated: Template import system has been removed."""
    raise HTTPException(status_code=410, detail="Template import system has been deprecated. Findings are now generated directly by analyzers.")

@router.get("/import/status/{job_id}")
async def get_import_status(job_id: str):
    """Deprecated: Template import system has been removed."""
    raise HTTPException(status_code=410, detail="Template import system has been deprecated.")

@router.delete("/import/jobs/{job_id}")
async def delete_import_job(job_id: str):
    """Deprecated: Template import system has been removed."""
    raise HTTPException(status_code=410, detail="Template import system has been deprecated.")

@router.get("/import/jobs")
async def list_import_jobs():
    """Deprecated: Template import system has been removed."""
    raise HTTPException(status_code=410, detail="Template import system has been deprecated.")
