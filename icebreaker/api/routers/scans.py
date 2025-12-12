"""
Scans API router - CRUD operations for scans.
"""
from __future__ import annotations
from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from fastapi.responses import FileResponse, StreamingResponse
from sqlalchemy.orm import Session
from sqlalchemy import desc
from typing import List, Optional
from pydantic import BaseModel, Field
from datetime import datetime
from pathlib import Path
import json
import io

from icebreaker.db.database import get_db
from icebreaker.db.models import Scan, Target, Service, Finding, ScanStatus
from icebreaker.core.models import RunContext, Target as CoreTarget
from icebreaker.engine.orchestrator import Orchestrator
from icebreaker.core.network_utils import expand_targets

router = APIRouter()


# Pydantic models for API
class ScanCreate(BaseModel):
    """Request model for creating a new scan."""
    name: Optional[str] = None
    targets: List[str] = Field(..., min_items=1)
    preset: str = "quick"
    ports: Optional[str] = None
    host_conc: int = 128
    svc_conc: int = 256
    timeout: float = 1.5
    insecure: bool = False
    ai_provider: Optional[str] = None
    ai_model: Optional[str] = None
    ai_base_url: Optional[str] = None


class ScanResponse(BaseModel):
    """Response model for scan data."""
    id: int
    run_id: str
    name: Optional[str]
    status: str
    preset: str
    started_at: datetime
    completed_at: Optional[datetime]
    duration_seconds: Optional[int]
    target_count: int
    services_found: int
    findings_count: int
    settings: dict

    class Config:
        from_attributes = True


class FindingResponse(BaseModel):
    """Response model for finding data."""
    id: int
    finding_id: str
    title: str
    severity: str
    target: str
    port: Optional[int]
    risk_score: Optional[float]
    confidence: float
    false_positive: bool

    class Config:
        from_attributes = True


@router.post("/scans", response_model=ScanResponse)
async def create_scan(
    scan_request: ScanCreate,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db)
):
    """
    Create and start a new scan.

    Args:
        scan_request: Scan configuration
        background_tasks: FastAPI background tasks
        db: Database session

    Returns:
        Created scan object
    """
    # Expand targets to handle CIDR notation (e.g., 192.168.1.0/24)
    expanded_targets = expand_targets(scan_request.targets)

    # Create scan record
    scan = Scan(
        run_id=f"web-{datetime.utcnow().strftime('%Y%m%dT%H%M%SZ')}",
        name=scan_request.name,
        status=ScanStatus.PENDING,
        preset=scan_request.preset,
        started_at=datetime.utcnow(),
        target_count=len(expanded_targets),
        settings={
            "ports": scan_request.ports,
            "host_conc": scan_request.host_conc,
            "svc_conc": scan_request.svc_conc,
            "timeout": scan_request.timeout,
            "insecure": scan_request.insecure,
            "ai_provider": scan_request.ai_provider,
            "ai_model": scan_request.ai_model,
            "ai_base_url": scan_request.ai_base_url,
        }
    )

    db.add(scan)
    db.commit()
    db.refresh(scan)

    # Create target records from expanded list
    for target_addr in expanded_targets:
        target = Target(scan_id=scan.id, address=target_addr)
        db.add(target)

    db.commit()

    # Queue scan execution
    background_tasks.add_task(execute_scan, scan.id)

    return scan


@router.get("/scans", response_model=List[ScanResponse])
async def list_scans(
    skip: int = 0,
    limit: int = 50,
    status: Optional[str] = None,
    db: Session = Depends(get_db)
):
    """
    List all scans with optional filtering.

    Args:
        skip: Number of scans to skip (pagination)
        limit: Maximum number of scans to return
        status: Filter by status
        db: Database session

    Returns:
        List of scans
    """
    query = db.query(Scan).order_by(desc(Scan.started_at))

    if status:
        query = query.filter(Scan.status == status)

    scans = query.offset(skip).limit(limit).all()
    return scans


@router.get("/scans/{scan_id}", response_model=ScanResponse)
async def get_scan(scan_id: int, db: Session = Depends(get_db)):
    """
    Get detailed scan information.

    Args:
        scan_id: Scan ID
        db: Database session

    Returns:
        Scan object with details
    """
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    return scan


@router.get("/scans/{scan_id}/findings", response_model=List[FindingResponse])
async def get_scan_findings(scan_id: int, db: Session = Depends(get_db)):
    """
    Get all findings for a scan.

    Args:
        scan_id: Scan ID
        db: Database session

    Returns:
        List of findings
    """
    findings = db.query(Finding).filter(Finding.scan_id == scan_id).order_by(desc(Finding.risk_score)).all()
    return findings


@router.get("/scans/{scan_id}/services")
async def get_scan_services(scan_id: int, db: Session = Depends(get_db)):
    """
    Get all services discovered in a scan.

    Args:
        scan_id: Scan ID
        db: Database session

    Returns:
        List of services
    """
    services = db.query(Service).filter(Service.scan_id == scan_id).all()
    return services


@router.delete("/scans/{scan_id}")
async def delete_scan(scan_id: int, db: Session = Depends(get_db)):
    """
    Delete a scan and all its data.

    Args:
        scan_id: Scan ID
        db: Database session

    Returns:
        Success message
    """
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    db.delete(scan)
    db.commit()

    return {"message": "Scan deleted successfully"}


@router.post("/scans/{scan_id}/findings/{finding_id}/false-positive")
async def mark_false_positive(scan_id: int, finding_id: int, db: Session = Depends(get_db)):
    """
    Mark a finding as false positive.

    Args:
        scan_id: Scan ID
        finding_id: Finding ID
        db: Database session

    Returns:
        Updated finding
    """
    finding = db.query(Finding).filter(
        Finding.scan_id == scan_id,
        Finding.id == finding_id
    ).first()

    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    finding.false_positive = not finding.false_positive
    db.commit()
    db.refresh(finding)

    return finding


@router.get("/scans/{scan_id}/export/{format}")
async def export_scan(scan_id: int, format: str, db: Session = Depends(get_db)):
    """
    Export scan results in various formats.

    Args:
        scan_id: Scan ID
        format: Export format (json, sarif, html, markdown)
        db: Database session

    Returns:
        File download
    """
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    # Get scan data
    findings = db.query(Finding).filter(Finding.scan_id == scan_id).all()
    services = db.query(Service).filter(Service.scan_id == scan_id).all()

    settings = scan.settings
    output_dir = settings.get('out_dir') or f"runs/{scan.run_id}"
    output_path = Path(output_dir)

    # Check format and return appropriate file
    if format == "json":
        # Export as JSON
        data = {
            "scan": {
                "id": scan.id,
                "run_id": scan.run_id,
                "name": scan.name,
                "status": scan.status.value,
                "started_at": scan.started_at.isoformat(),
                "completed_at": scan.completed_at.isoformat() if scan.completed_at else None,
                "preset": scan.preset,
                "settings": scan.settings
            },
            "services": [
                {
                    "target": s.target,
                    "port": s.port,
                    "name": s.name,
                    "meta": s.meta
                }
                for s in services
            ],
            "findings": [
                {
                    "id": f.finding_id,
                    "title": f.title,
                    "severity": f.severity,
                    "target": f.target,
                    "port": f.port,
                    "tags": f.tags,
                    "details": f.details,
                    "confidence": f.confidence,
                    "risk_score": f.risk_score,
                    "recommendation": f.recommendation
                }
                for f in findings
            ]
        }
        json_str = json.dumps(data, indent=2)
        return StreamingResponse(
            io.BytesIO(json_str.encode()),
            media_type="application/json",
            headers={"Content-Disposition": f"attachment; filename={scan.run_id}.json"}
        )

    elif format == "sarif":
        # Return SARIF file if it exists
        sarif_file = output_path / "results.sarif"
        if sarif_file.exists():
            return FileResponse(
                sarif_file,
                media_type="application/json",
                filename=f"{scan.run_id}.sarif"
            )
        else:
            raise HTTPException(status_code=404, detail="SARIF file not found")

    elif format == "html":
        # Return HTML report if it exists
        html_file = output_path / "report.html"
        if html_file.exists():
            return FileResponse(
                html_file,
                media_type="text/html",
                filename=f"{scan.run_id}.html"
            )
        else:
            raise HTTPException(status_code=404, detail="HTML report not found")

    elif format == "markdown":
        # Return Markdown summary if it exists
        md_file = output_path / "summary.md"
        if md_file.exists():
            return FileResponse(
                md_file,
                media_type="text/markdown",
                filename=f"{scan.run_id}.md"
            )
        else:
            raise HTTPException(status_code=404, detail="Markdown file not found")

    else:
        raise HTTPException(status_code=400, detail=f"Unsupported export format: {format}")


@router.get("/scans/compare/{scan_id_1}/{scan_id_2}")
async def compare_scans(scan_id_1: int, scan_id_2: int, db: Session = Depends(get_db)):
    """
    Compare two scans and show differences.

    Args:
        scan_id_1: First scan ID (baseline)
        scan_id_2: Second scan ID (comparison)
        db: Database session

    Returns:
        Comparison results
    """
    # Get both scans
    scan1 = db.query(Scan).filter(Scan.id == scan_id_1).first()
    scan2 = db.query(Scan).filter(Scan.id == scan_id_2).first()

    if not scan1 or not scan2:
        raise HTTPException(status_code=404, detail="One or both scans not found")

    # Get findings for both scans
    findings1 = db.query(Finding).filter(Finding.scan_id == scan_id_1).all()
    findings2 = db.query(Finding).filter(Finding.scan_id == scan_id_2).all()

    # Create finding signatures for comparison
    def finding_signature(f: Finding) -> str:
        return f"{f.target}:{f.port}:{f.title}:{f.severity}"

    findings1_sigs = {finding_signature(f): f for f in findings1}
    findings2_sigs = {finding_signature(f): f for f in findings2}

    # Calculate differences
    fixed = []  # In scan1 but not in scan2
    new = []  # In scan2 but not in scan1
    unchanged = []  # In both scans

    for sig, finding in findings1_sigs.items():
        if sig not in findings2_sigs:
            fixed.append({
                "id": finding.id,
                "title": finding.title,
                "severity": finding.severity,
                "target": finding.target,
                "port": finding.port,
                "risk_score": finding.risk_score
            })
        else:
            unchanged.append({
                "id": finding.id,
                "title": finding.title,
                "severity": finding.severity,
                "target": finding.target,
                "port": finding.port,
                "risk_score": finding.risk_score
            })

    for sig, finding in findings2_sigs.items():
        if sig not in findings1_sigs:
            new.append({
                "id": finding.id,
                "title": finding.title,
                "severity": finding.severity,
                "target": finding.target,
                "port": finding.port,
                "risk_score": finding.risk_score
            })

    # Calculate risk score changes
    total_risk_1 = sum(f.risk_score or 0 for f in findings1)
    total_risk_2 = sum(f.risk_score or 0 for f in findings2)
    risk_change = total_risk_2 - total_risk_1
    risk_change_percent = (risk_change / total_risk_1 * 100) if total_risk_1 > 0 else 0

    return {
        "scan1": {
            "id": scan1.id,
            "run_id": scan1.run_id,
            "name": scan1.name,
            "started_at": scan1.started_at,
            "findings_count": len(findings1),
            "total_risk": total_risk_1
        },
        "scan2": {
            "id": scan2.id,
            "run_id": scan2.run_id,
            "name": scan2.name,
            "started_at": scan2.started_at,
            "findings_count": len(findings2),
            "total_risk": total_risk_2
        },
        "comparison": {
            "fixed": fixed,
            "new": new,
            "unchanged": unchanged,
            "fixed_count": len(fixed),
            "new_count": len(new),
            "unchanged_count": len(unchanged),
            "risk_change": risk_change,
            "risk_change_percent": risk_change_percent
        }
    }


async def execute_scan(scan_id: int):
    """
    Execute a scan in the background.

    This function runs the actual Icebreaker scan and stores results in the database.

    Args:
        scan_id: Scan ID to execute
    """
    import asyncio
    from pathlib import Path
    from icebreaker.db.database import SessionLocal
    from icebreaker.api.websocket import manager
    from icebreaker.core.port_parser import parse_port_spec, get_top_ports
    from icebreaker.detectors.tcp_probe import TCPProbe
    from icebreaker.detectors.banner_grab import BannerGrab
    from icebreaker.analyzers.http_basic import HTTPBasic
    from icebreaker.analyzers.security_headers import SecurityHeaders
    from icebreaker.analyzers.tls_analyzer import TLSAnalyzer
    from icebreaker.analyzers.info_disclosure import InfoDisclosure
    from icebreaker.writers.jsonl import JSONLWriter
    from icebreaker.writers.markdown import MarkdownWriter
    from icebreaker.writers.sarif import SARIFWriter
    from icebreaker.writers.html_writer import HTMLWriter

    try:
        from icebreaker.analyzers.ssh_banner import SSHBanner
        _HAS_SSH = True
    except Exception:
        _HAS_SSH = False

    try:
        from icebreaker.writers.ai_summary import AISummaryWriter
        _HAS_AI_WRITER = True
    except Exception:
        _HAS_AI_WRITER = False

    db = SessionLocal()

    try:
        # Get scan record and targets
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if not scan:
            return

        targets = db.query(Target).filter(Target.scan_id == scan_id).all()
        if not targets:
            scan.status = ScanStatus.FAILED
            scan.error_message = "No targets specified"
            db.commit()
            return

        # Update status to running
        scan.status = ScanStatus.RUNNING
        db.commit()

        # Send WebSocket update
        await manager.send_update(scan_id, {
            "type": "scan_status",
            "data": {"status": "running", "message": "Scan started"}
        })

        # Build run context
        settings = scan.settings
        ctx = RunContext.new(
            preset=scan.preset,
            out_dir=settings.get('out_dir') or f"runs/{scan.run_id}",
            settings={"quiet": True}
        )

        # Create output directory
        Path(ctx.out_dir).mkdir(parents=True, exist_ok=True)

        # Parse port specification
        port_list = None
        ports_config = settings.get('ports')
        if ports_config:
            if ports_config.lower() == 'top100':
                port_list = get_top_ports(100)
            elif ports_config.lower() == 'top1000':
                port_list = get_top_ports(1000)
            else:
                try:
                    port_list = parse_port_spec(ports_config)
                except ValueError:
                    pass  # Use defaults

        # Set up detectors
        timeout = settings.get('timeout', 1.5)
        insecure = settings.get('insecure', False)
        host_conc = settings.get('host_conc', 128)

        detectors = [
            TCPProbe(timeout=timeout, quiet=True, ports=port_list, max_concurrent=host_conc),
            BannerGrab(timeout=timeout, quiet=True, insecure=insecure),
        ]

        # Set up analyzers
        analyzers = [
            HTTPBasic(),
            SecurityHeaders(),
            TLSAnalyzer(),
            InfoDisclosure(),
        ]
        if _HAS_SSH:
            analyzers.append(SSHBanner())

        # Add advanced analyzers
        try:
            from icebreaker.analyzers.ssl_cert import SSLCertAnalyzer
            analyzers.append(SSLCertAnalyzer())
        except Exception:
            pass

        try:
            from icebreaker.analyzers.waf_cdn import WAFCDNDetector
            analyzers.append(WAFCDNDetector())
        except Exception:
            pass

        try:
            from icebreaker.analyzers.api_discovery import APIDiscovery
            analyzers.append(APIDiscovery())
        except Exception:
            pass

        # Set up writers
        writers = [JSONLWriter(), MarkdownWriter(), SARIFWriter(), HTMLWriter()]

        # Add AI writer if configured
        if _HAS_AI_WRITER and settings.get('ai_provider'):
            try:
                ai_writer = AISummaryWriter(
                    ai_provider=settings['ai_provider'],
                    ai_model=settings.get('ai_model'),
                    base_url=settings.get('ai_base_url')
                )
                writers.append(ai_writer)
            except Exception as e:
                print(f"Failed to initialize AI writer: {e}")

        # Create orchestrator
        orch = Orchestrator(
            ctx,
            detectors=detectors,
            analyzers=analyzers,
            writers=writers,
            host_conc=settings.get('host_conc', 128),
            svc_conc=settings.get('svc_conc', 256),
            quiet=True
        )

        # Convert targets to core Target objects
        core_targets = [CoreTarget(address=t.address) for t in targets]

        # Run scan
        await manager.send_update(scan_id, {
            "type": "scan_progress",
            "data": {"stage": "discovery", "message": "Discovering services..."}
        })
        discovered_services = await orch.discover(core_targets)

        await manager.send_update(scan_id, {
            "type": "scan_progress",
            "data": {"stage": "analysis", "message": f"Analyzing {len(discovered_services)} services..."}
        })
        discovered_findings = await orch.analyse(discovered_services)

        await manager.send_update(scan_id, {
            "type": "scan_progress",
            "data": {"stage": "writing", "message": "Generating reports..."}
        })
        orch.write_outputs(discovered_services, discovered_findings)

        # Store services in database
        for svc in discovered_services:
            db_service = Service(
                scan_id=scan.id,
                target=svc.target,
                port=svc.port,
                name=svc.name,
                meta=svc.meta or {}
            )
            db.add(db_service)

        # Store findings in database
        for finding in discovered_findings:
            db_finding = Finding(
                scan_id=scan.id,
                finding_id=finding.id,
                title=finding.title,
                severity=finding.severity,
                target=finding.target,
                port=finding.port,
                tags=finding.tags or [],
                details=finding.details or {},
                confidence=finding.confidence,
                risk_score=finding.risk_score,
                recommendation=finding.recommendation,
                false_positive=False
            )
            db.add(db_finding)

        # Update scan with results
        scan.status = ScanStatus.COMPLETED
        scan.completed_at = datetime.utcnow()
        scan.duration_seconds = int((scan.completed_at - scan.started_at).total_seconds())
        scan.services_found = len(discovered_services)
        scan.findings_count = len(discovered_findings)
        db.commit()

        # Send completion update
        await manager.send_update(scan_id, {
            "type": "scan_complete",
            "data": {
                "status": "completed",
                "services_found": len(discovered_services),
                "findings_count": len(discovered_findings),
                "duration": scan.duration_seconds
            }
        })

    except Exception as e:
        # Mark as failed
        import traceback
        error_details = traceback.format_exc()
        scan.status = ScanStatus.FAILED
        scan.error_message = f"{str(e)}\n\n{error_details}"
        scan.completed_at = datetime.utcnow()
        scan.duration_seconds = int((scan.completed_at - scan.started_at).total_seconds())
        db.commit()

        # Send failure update
        await manager.send_update(scan_id, {
            "type": "scan_failed",
            "data": {
                "status": "failed",
                "error": str(e)
            }
        })

    finally:
        db.close()
