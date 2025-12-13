"""
API endpoints for importing finding templates from external sources.
"""
from fastapi import APIRouter, UploadFile, File, Depends, HTTPException, BackgroundTasks
from sqlalchemy.orm import Session
from typing import Dict, Any
import tarfile
import tempfile
import shutil
from pathlib import Path
from datetime import datetime

from icebreaker.db.database import get_db
from icebreaker.db.models import FindingTemplate
from icebreaker.importers.nasl_parser import NASLParser


router = APIRouter()

# Store import job status
import_jobs: Dict[str, Dict[str, Any]] = {}


@router.post("/import/nessus")
async def import_nessus_plugins(
    background_tasks: BackgroundTasks,
    file: UploadFile = File(...),
    db: Session = Depends(get_db)
):
    """
    Import Nessus plugins from an uploaded tar file.

    Accepts .tar, .tar.gz, .tgz files containing .nasl plugin files.
    """
    # Validate file type
    if not file.filename:
        raise HTTPException(status_code=400, detail="No filename provided")

    valid_extensions = ['.tar', '.tar.gz', '.tgz', '.tar.bz2']
    if not any(file.filename.endswith(ext) for ext in valid_extensions):
        raise HTTPException(
            status_code=400,
            detail=f"Invalid file type. Must be one of: {', '.join(valid_extensions)}"
        )

    # Create import job ID
    job_id = f"import_{datetime.now().strftime('%Y%m%d_%H%M%S')}"

    # Initialize job status
    import_jobs[job_id] = {
        'status': 'processing',
        'total': 0,
        'processed': 0,
        'imported': 0,
        'skipped': 0,
        'errors': [],
        'started_at': datetime.now().isoformat()
    }

    # Process in background
    background_tasks.add_task(
        process_nessus_tar,
        job_id,
        file,
        db
    )

    return {
        'job_id': job_id,
        'message': 'Import started',
        'status_url': f'/api/import/status/{job_id}'
    }


@router.get("/import/status/{job_id}")
async def get_import_status(job_id: str):
    """Get the status of an import job."""
    if job_id not in import_jobs:
        raise HTTPException(status_code=404, detail="Import job not found")

    return import_jobs[job_id]


async def process_nessus_tar(job_id: str, file: UploadFile, db: Session):
    """
    Process Nessus tar file in background.

    Args:
        job_id: Import job identifier
        file: Uploaded tar file
        db: Database session
    """
    temp_dir = None

    try:
        # Create temporary directory
        temp_dir = tempfile.mkdtemp(prefix='nessus_import_')
        temp_path = Path(temp_dir)

        # Save uploaded file
        tar_path = temp_path / file.filename
        with open(tar_path, 'wb') as f:
            content = await file.read()
            f.write(content)

        # Extract tar file
        extract_dir = temp_path / 'extracted'
        extract_dir.mkdir()

        with tarfile.open(tar_path, 'r:*') as tar:
            # Security check: ensure no path traversal
            for member in tar.getmembers():
                if member.name.startswith('/') or '..' in member.name:
                    continue
                tar.extract(member, extract_dir)

        # Find all .nasl files
        nasl_files = list(extract_dir.rglob('*.nasl'))
        import_jobs[job_id]['total'] = len(nasl_files)

        # Parse and import
        parser = NASLParser()
        imported = 0
        skipped = 0
        errors = []

        for nasl_file in nasl_files:
            try:
                # Parse NASL file
                metadata = parser.parse_file(str(nasl_file))

                if not metadata:
                    skipped += 1
                    import_jobs[job_id]['processed'] += 1
                    continue

                # Convert to template format
                template_data = parser.to_finding_template(metadata)

                # Check if already exists
                existing = db.query(FindingTemplate).filter(
                    FindingTemplate.finding_id == template_data['finding_id']
                ).first()

                if existing:
                    # Update existing
                    for key, value in template_data.items():
                        if hasattr(existing, key) and value is not None:
                            setattr(existing, key, value)
                    skipped += 1
                else:
                    # Create new
                    template = FindingTemplate(**template_data)
                    db.add(template)
                    imported += 1

                import_jobs[job_id]['processed'] += 1

                # Commit in batches of 100
                if (imported + skipped) % 100 == 0:
                    db.commit()

            except Exception as e:
                error_msg = f"Error processing {nasl_file.name}: {str(e)}"
                errors.append(error_msg)
                if len(errors) <= 10:  # Only store first 10 errors
                    import_jobs[job_id]['errors'].append(error_msg)

        # Final commit
        db.commit()

        # Update job status
        import_jobs[job_id].update({
            'status': 'completed',
            'imported': imported,
            'skipped': skipped,
            'completed_at': datetime.now().isoformat()
        })

    except Exception as e:
        import_jobs[job_id].update({
            'status': 'failed',
            'error': str(e),
            'completed_at': datetime.now().isoformat()
        })
        db.rollback()

    finally:
        # Cleanup temporary directory
        if temp_dir and Path(temp_dir).exists():
            shutil.rmtree(temp_dir)


@router.delete("/import/jobs/{job_id}")
async def delete_import_job(job_id: str):
    """Delete an import job from history."""
    if job_id not in import_jobs:
        raise HTTPException(status_code=404, detail="Import job not found")

    del import_jobs[job_id]
    return {'message': 'Import job deleted'}


@router.get("/import/jobs")
async def list_import_jobs():
    """List all import jobs."""
    return {
        'jobs': [
            {'job_id': job_id, **job_data}
            for job_id, job_data in import_jobs.items()
        ]
    }
