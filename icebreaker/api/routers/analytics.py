"""
Analytics API router - Aggregate statistics and metrics for reporting.
"""
from __future__ import annotations
from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session
from sqlalchemy import func, desc
from typing import Dict, List, Any, Optional
from collections import defaultdict
from datetime import datetime, timedelta

from icebreaker.db.database import get_db
from icebreaker.db.models import Scan, Finding, Service, ScanStatus
from icebreaker.core.network_topology import NetworkTopology

router = APIRouter()


@router.get("/analytics/dashboard")
async def get_dashboard_analytics(db: Session = Depends(get_db)) -> Dict[str, Any]:
    """
    Get comprehensive dashboard analytics.

    Returns:
        Dictionary with various analytics metrics
    """
    # Scan statistics
    total_scans = db.query(Scan).count()
    active_scans = db.query(Scan).filter(
        Scan.status.in_([ScanStatus.RUNNING, ScanStatus.PENDING])
    ).count()
    completed_scans = db.query(Scan).filter(Scan.status == ScanStatus.COMPLETED).count()
    failed_scans = db.query(Scan).filter(Scan.status == ScanStatus.FAILED).count()

    # Finding statistics by severity
    severity_counts = db.query(
        Finding.severity,
        func.count(Finding.id)
    ).filter(
        Finding.false_positive == False
    ).group_by(Finding.severity).all()

    severity_distribution = {
        "CRITICAL": 0,
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0,
        "INFO": 0
    }

    for severity, count in severity_counts:
        severity_distribution[severity.upper()] = count

    # Finding statistics by status
    status_counts = db.query(
        Finding.status,
        func.count(Finding.id)
    ).filter(
        Finding.false_positive == False
    ).group_by(Finding.status).all()

    status_distribution = {status: count for status, count in status_counts}

    # Total findings
    total_findings = db.query(Finding).filter(Finding.false_positive == False).count()
    false_positives = db.query(Finding).filter(Finding.false_positive == True).count()

    # Top vulnerable targets
    top_targets = db.query(
        Finding.target,
        func.count(Finding.id).label('finding_count'),
        func.avg(Finding.risk_score).label('avg_risk_score')
    ).filter(
        Finding.false_positive == False
    ).group_by(Finding.target).order_by(desc('finding_count')).limit(10).all()

    top_targets_list = [
        {
            "target": target,
            "finding_count": count,
            "avg_risk_score": round(float(avg_risk) if avg_risk else 0, 2)
        }
        for target, count, avg_risk in top_targets
    ]

    # Findings by category (from templates)
    category_counts = db.query(
        Finding.finding_id,
        func.count(Finding.id).label('count')
    ).filter(
        Finding.false_positive == False
    ).group_by(Finding.finding_id).order_by(desc('count')).limit(10).all()

    category_distribution = [
        {"finding_type": finding_id, "count": count}
        for finding_id, count in category_counts
    ]

    # Recent scan activity (last 30 days)
    thirty_days_ago = datetime.utcnow() - timedelta(days=30)
    recent_scans = db.query(
        func.date(Scan.started_at).label('date'),
        func.count(Scan.id).label('count')
    ).filter(
        Scan.started_at >= thirty_days_ago
    ).group_by(func.date(Scan.started_at)).order_by('date').all()

    scan_timeline = [
        {"date": str(date), "count": count}
        for date, count in recent_scans
    ]

    # Risk score calculation
    high_risk_findings = db.query(Finding).filter(
        Finding.false_positive == False,
        Finding.severity.in_(['CRITICAL', 'HIGH'])
    ).count()

    # Simple risk score: weighted by severity
    risk_weights = {
        'CRITICAL': 10,
        'HIGH': 7,
        'MEDIUM': 4,
        'LOW': 2,
        'INFO': 1
    }

    total_risk_score = sum(
        severity_distribution.get(sev, 0) * weight
        for sev, weight in risk_weights.items()
    )

    # Normalize to 0-100 scale (assuming 100 findings of each severity = 100 score)
    max_possible_score = 100 * sum(risk_weights.values())
    normalized_risk_score = min(100, int((total_risk_score / max_possible_score) * 100))

    # Compliance statistics (findings with compliance mappings)
    findings_with_cwe = db.query(Finding).join(
        Finding.template
    ).filter(
        Finding.false_positive == False,
        Finding.template.has()
    ).count()

    return {
        "scans": {
            "total": total_scans,
            "active": active_scans,
            "completed": completed_scans,
            "failed": failed_scans
        },
        "findings": {
            "total": total_findings,
            "false_positives": false_positives,
            "high_risk": high_risk_findings,
            "severity_distribution": severity_distribution,
            "status_distribution": status_distribution,
            "by_category": category_distribution
        },
        "risk": {
            "overall_score": normalized_risk_score,
            "total_risk_points": total_risk_score
        },
        "targets": {
            "top_vulnerable": top_targets_list
        },
        "timeline": {
            "scans_30_days": scan_timeline
        },
        "compliance": {
            "findings_with_mappings": findings_with_cwe,
            "coverage_percentage": round((findings_with_cwe / total_findings * 100) if total_findings > 0 else 0, 1)
        }
    }


@router.get("/analytics/scans/{scan_id}/summary")
async def get_scan_summary(scan_id: int, db: Session = Depends(get_db)) -> Dict[str, Any]:
    """
    Get detailed analytics for a specific scan.

    Args:
        scan_id: Scan ID
        db: Database session

    Returns:
        Dictionary with scan-specific analytics
    """
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        return {"error": "Scan not found"}

    # Finding statistics
    findings = db.query(Finding).filter(Finding.scan_id == scan_id).all()

    severity_counts = defaultdict(int)
    status_counts = defaultdict(int)
    port_counts = defaultdict(int)

    for finding in findings:
        if not finding.false_positive:
            severity_counts[finding.severity] += 1
            status_counts[finding.status] += 1
            if finding.port:
                port_counts[finding.port] += 1

    # Top ports with findings
    top_ports = sorted(
        [{"port": port, "count": count} for port, count in port_counts.items()],
        key=lambda x: x['count'],
        reverse=True
    )[:10]

    # Services discovered
    services = db.query(Service).filter(Service.scan_id == scan_id).all()
    service_names = defaultdict(int)
    for service in services:
        if service.name:
            service_names[service.name] += 1

    top_services = sorted(
        [{"name": name, "count": count} for name, count in service_names.items()],
        key=lambda x: x['count'],
        reverse=True
    )[:10]

    return {
        "scan_id": scan_id,
        "scan_name": scan.name or scan.run_id,
        "status": scan.status.value,
        "findings": {
            "total": len([f for f in findings if not f.false_positive]),
            "false_positives": len([f for f in findings if f.false_positive]),
            "severity_distribution": dict(severity_counts),
            "status_distribution": dict(status_counts),
            "by_port": top_ports
        },
        "services": {
            "total": len(services),
            "by_name": top_services
        },
        "targets": {
            "total": scan.target_count,
            "alive": scan.alive_hosts
        }
    }


@router.get("/analytics/network-topology")
async def get_network_topology(
    scan_ids: Optional[List[int]] = Query(None),
    limit: Optional[int] = Query(None, description="Limit number of nodes"),
    db: Session = Depends(get_db)
) -> Dict[str, Any]:
    """
    Get network topology graph from scan results.

    Args:
        scan_ids: Optional list of scan IDs to include (None = all scans)
        limit: Optional limit on number of nodes (for performance)
        db: Database session

    Returns:
        Dictionary with nodes and edges for network visualization
    """
    topology = NetworkTopology(db)
    return topology.build_topology(scan_ids=scan_ids, limit=limit)
