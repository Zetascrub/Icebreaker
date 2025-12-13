"""
API endpoints for importing finding templates from external sources.
"""
from fastapi import APIRouter, UploadFile, File, Depends, HTTPException, BackgroundTasks
from sqlalchemy.orm import Session
from typing import Dict, Any, List, Optional
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

# Store preview data temporarily
preview_cache: Dict[str, Dict[str, Any]] = {}


@router.post("/import/nessus/preview")
async def preview_nessus_plugins(
    file: UploadFile = File(...),
    sample_size: int = 20,
    db: Session = Depends(get_db)
):
    """
    Preview Nessus plugins from tar file without importing.

    Validates the file, parses a sample of plugins, and returns statistics
    and sample data for user verification before actual import.

    Args:
        file: Uploaded tar file
        sample_size: Number of plugins to parse as sample (default 20)
        db: Database session

    Returns:
        Preview data including stats, samples, and errors
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

    temp_dir = None
    preview_id = f"preview_{datetime.now().strftime('%Y%m%d_%H%M%S')}"

    try:
        # Create temporary directory
        temp_dir = tempfile.mkdtemp(prefix='nessus_preview_')
        temp_path = Path(temp_dir)

        # Save uploaded file
        tar_path = temp_path / file.filename
        file_content = await file.read()

        # Check if file content is actually received
        if len(file_content) == 0:
            raise HTTPException(status_code=400, detail="Uploaded file is empty")

        # Check file signature (magic bytes)
        file_type = "unknown"
        if file_content[:2] == b'\x1f\x8b':  # gzip
            file_type = "gzip"
        elif file_content[:3] == b'BZh':  # bzip2
            file_type = "bzip2"
        elif file_content[:262:].startswith(b'ustar'):  # uncompressed tar
            file_type = "tar"
        elif file_content[:512:].endswith(b'ustar\x00'):
            file_type = "tar"

        with open(tar_path, 'wb') as f:
            f.write(file_content)

        # Extract tar file
        extract_dir = temp_path / 'extracted'
        extract_dir.mkdir()

        # Validate tar file
        try:
            with tarfile.open(tar_path, 'r:*') as tar:
                # Security check: ensure no path traversal
                for member in tar.getmembers():
                    if member.name.startswith('/') or '..' in member.name:
                        continue
                    tar.extract(member, extract_dir)
        except tarfile.ReadError as e:
            error_detail = (
                f"Invalid tar archive (detected type: {file_type}). "
                f"Please ensure you're uploading a Nessus plugin archive (.tar, .tar.gz, or .tgz). "
                f"File size: {len(file_content)} bytes. "
                f"Error: {str(e)}"
            )
            raise HTTPException(status_code=400, detail=error_detail)
        except Exception as e:
            raise HTTPException(
                status_code=400,
                detail=f"Failed to extract tar archive: {str(e)}"
            )

        # Find all .nasl files
        nasl_files = list(extract_dir.rglob('*.nasl'))
        total_files = len(nasl_files)

        if total_files == 0:
            raise HTTPException(status_code=400, detail="No .nasl files found in archive")

        # Parse sample of plugins
        parser = NASLParser()
        samples: List[Dict[str, Any]] = []
        parse_errors: List[Dict[str, str]] = []
        valid_count = 0
        invalid_count = 0

        # Sample files (take evenly distributed samples)
        sample_indices = list(range(0, total_files, max(1, total_files // sample_size)))[:sample_size]
        sample_files = [nasl_files[i] for i in sample_indices]

        for nasl_file in sample_files:
            try:
                # Parse NASL file
                metadata = parser.parse_file(str(nasl_file))

                if metadata:
                    # Convert to template format
                    template_data = parser.to_finding_template(metadata)

                    # Check if would be duplicate
                    existing = db.query(FindingTemplate).filter(
                        FindingTemplate.finding_id == template_data['finding_id']
                    ).first()

                    samples.append({
                        'filename': nasl_file.name,
                        'finding_id': template_data['finding_id'],
                        'title': template_data['title'],
                        'category': template_data.get('category'),
                        'severity': template_data['severity'],
                        'cvss_score': template_data.get('cvss_score'),
                        'has_remediation': bool(template_data.get('remediation')),
                        'has_description': bool(template_data.get('description')),
                        'exists_in_db': bool(existing),
                        'cwe_id': template_data.get('cwe_id'),
                        'reference_count': len(template_data.get('references', []))
                    })
                    valid_count += 1
                else:
                    invalid_count += 1
                    parse_errors.append({
                        'filename': nasl_file.name,
                        'error': 'Failed to parse metadata (no title found)'
                    })

            except Exception as e:
                invalid_count += 1
                parse_errors.append({
                    'filename': nasl_file.name,
                    'error': str(e)
                })

        # Calculate statistics
        estimated_valid = int((valid_count / len(sample_files)) * total_files) if sample_files else 0
        estimated_invalid = total_files - estimated_valid

        # Check for existing templates that would be updated
        existing_count = sum(1 for s in samples if s['exists_in_db'])
        estimated_new = estimated_valid - int((existing_count / len(samples)) * estimated_valid) if samples else 0
        estimated_updates = estimated_valid - estimated_new

        # Store preview data in cache for import confirmation
        preview_data = {
            'preview_id': preview_id,
            'filename': file.filename,
            'file_size': len(file_content),
            'total_files': total_files,
            'sample_size': len(sample_files),
            'valid_count': valid_count,
            'invalid_count': invalid_count,
            'estimated_valid': estimated_valid,
            'estimated_invalid': estimated_invalid,
            'estimated_new': estimated_new,
            'estimated_updates': estimated_updates,
            'samples': samples,
            'errors': parse_errors[:10],  # First 10 errors
            'created_at': datetime.now().isoformat()
        }

        # Save file for later import
        saved_file_path = temp_path / 'saved_file.tar'
        shutil.copy(tar_path, saved_file_path)
        preview_data['saved_file_path'] = str(saved_file_path)
        preview_data['temp_dir'] = temp_dir

        # Cache preview (don't delete temp_dir yet)
        preview_cache[preview_id] = preview_data

        # Return preview without temp_dir path
        response_data = preview_data.copy()
        del response_data['saved_file_path']
        del response_data['temp_dir']

        return response_data

    except HTTPException:
        # Cleanup on validation errors
        if temp_dir and Path(temp_dir).exists():
            shutil.rmtree(temp_dir)
        raise
    except Exception as e:
        # Cleanup on unexpected errors
        if temp_dir and Path(temp_dir).exists():
            shutil.rmtree(temp_dir)
        raise HTTPException(status_code=500, detail=f"Preview failed: {str(e)}")


@router.post("/import/nessus/confirm/{preview_id}")
async def confirm_nessus_import(
    preview_id: str,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db)
):
    """
    Confirm and execute import after preview validation.

    Args:
        preview_id: ID from the preview request
        background_tasks: FastAPI background tasks
        db: Database session

    Returns:
        Import job details
    """
    # Get preview data
    if preview_id not in preview_cache:
        raise HTTPException(status_code=404, detail="Preview not found or expired")

    preview_data = preview_cache[preview_id]

    # Create import job ID
    job_id = f"import_{datetime.now().strftime('%Y%m%d_%H%M%S')}"

    # Initialize job status
    import_jobs[job_id] = {
        'status': 'processing',
        'total': preview_data['total_files'],
        'processed': 0,
        'imported': 0,
        'skipped': 0,
        'errors': [],
        'started_at': datetime.now().isoformat(),
        'preview_id': preview_id
    }

    # Process in background
    background_tasks.add_task(
        process_confirmed_import,
        job_id,
        preview_id,
        db
    )

    return {
        'job_id': job_id,
        'message': 'Import started',
        'status_url': f'/api/import/status/{job_id}'
    }


async def process_confirmed_import(job_id: str, preview_id: str, db: Session):
    """
    Process confirmed import using cached preview data.

    Args:
        job_id: Import job identifier
        preview_id: Preview cache identifier
        db: Database session
    """
    preview_data = preview_cache.get(preview_id)
    if not preview_data:
        import_jobs[job_id]['status'] = 'failed'
        import_jobs[job_id]['error'] = 'Preview data not found'
        return

    temp_dir = preview_data.get('temp_dir')

    try:
        extract_dir = Path(temp_dir) / 'extracted'

        # Find all .nasl files
        nasl_files = list(extract_dir.rglob('*.nasl'))

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
                if len(import_jobs[job_id]['errors']) < 10:
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
        # Cleanup temporary directory and preview cache
        if temp_dir and Path(temp_dir).exists():
            shutil.rmtree(temp_dir)
        if preview_id in preview_cache:
            del preview_cache[preview_id]


@router.delete("/import/preview/{preview_id}")
async def cancel_preview(preview_id: str):
    """Cancel a preview and cleanup cached data."""
    if preview_id not in preview_cache:
        raise HTTPException(status_code=404, detail="Preview not found")

    preview_data = preview_cache[preview_id]
    temp_dir = preview_data.get('temp_dir')

    # Cleanup temp directory
    if temp_dir and Path(temp_dir).exists():
        shutil.rmtree(temp_dir)

    # Remove from cache
    del preview_cache[preview_id]

    return {'message': 'Preview cancelled and cleaned up'}


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
