"""
Export API router - Export scan data in various formats (CSV, JSON, SARIF, Markdown).
"""
from __future__ import annotations
from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import StreamingResponse, Response
from sqlalchemy.orm import Session
from typing import Dict, Any, List
from datetime import datetime
import csv
import json
import io

from icebreaker.db.database import get_db
from icebreaker.db.models import Scan, Finding, Service, Target
from fastapi import UploadFile, File
import uuid

router = APIRouter()


@router.get("/exports/scans/{scan_id}/findings.csv")
async def export_findings_csv(scan_id: int, db: Session = Depends(get_db)):
    """Export findings as CSV for spreadsheet analysis."""
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    findings = db.query(Finding).filter(Finding.scan_id == scan_id).all()

    # Create CSV in memory
    output = io.StringIO()
    writer = csv.writer(output)

    # Write header
    writer.writerow([
        'Finding ID', 'Title', 'Severity', 'Status', 'Target', 'Port',
        'Confidence', 'Risk Score', 'False Positive', 'Tags',
        'CWE', 'OWASP', 'PCI DSS', 'NIST CSF',
        'Description', 'Impact', 'Recommendation'
    ])

    # Write findings
    for finding in findings:
        writer.writerow([
            finding.finding_id,
            finding.title,
            finding.severity,
            finding.status,
            finding.target,
            finding.port or '',
            finding.confidence,
            finding.risk_score or '',
            'Yes' if finding.false_positive else 'No',
            ', '.join(finding.tags) if finding.tags else '',
            (finding.details or {}).get('cwe_id', ''),
            '',
            '',
            '',
            finding.description or '',
            finding.impact or '',
            finding.recommendation or ''
        ])

    # Return CSV file
    output.seek(0)
    headers = {
        'Content-Disposition': f'attachment; filename="findings-scan-{scan_id}-{datetime.utcnow().strftime("%Y%m%d")}.csv"'
    }
    return Response(content=output.getvalue(), media_type='text/csv', headers=headers)


@router.get("/exports/scans/{scan_id}/services.csv")
async def export_services_csv(scan_id: int, db: Session = Depends(get_db)):
    """Export discovered services as CSV."""
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    services = db.query(Service).filter(Service.scan_id == scan_id).all()

    # Create CSV in memory
    output = io.StringIO()
    writer = csv.writer(output)

    # Write header
    writer.writerow(['Target', 'Port', 'Service Name', 'Metadata'])

    # Write services
    for service in services:
        meta_str = json.dumps(service.meta) if service.meta else ''
        writer.writerow([
            service.target,
            service.port,
            service.name or 'Unknown',
            meta_str
        ])

    # Return CSV file
    output.seek(0)
    headers = {
        'Content-Disposition': f'attachment; filename="services-scan-{scan_id}-{datetime.utcnow().strftime("%Y%m%d")}.csv"'
    }
    return Response(content=output.getvalue(), media_type='text/csv', headers=headers)


@router.get("/exports/scans/{scan_id}/findings.json")
async def export_findings_json(scan_id: int, db: Session = Depends(get_db)):
    """Export findings as JSON for custom tooling."""
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    findings = db.query(Finding).filter(Finding.scan_id == scan_id).all()

    # Build JSON structure
    export_data = {
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
        "findings": [
            {
                "id": f.id,
                "finding_id": f.finding_id,
                "title": f.title,
                "severity": f.severity,
                "status": f.status,
                "target": f.target,
                "port": f.port,
                "confidence": f.confidence,
                "risk_score": f.risk_score,
                "false_positive": f.false_positive,
                "tags": f.tags,
                "details": f.details,
                "recommendation": f.recommendation,
                "cwe_id": (f.details or {}).get('cwe_id'),
                "cvss_score": (f.details or {}).get('cvss3_base_score') or (f.details or {}).get('cvss_base_score'),
                "description": f.description,
                "impact": f.impact,
                "remediation": f.recommendation,
                "created_at": f.created_at.isoformat(),
                "updated_at": f.updated_at.isoformat()
            }
            for f in findings
        ],
        "exported_at": datetime.utcnow().isoformat()
    }

    # Return JSON file
    headers = {
        'Content-Disposition': f'attachment; filename="findings-scan-{scan_id}-{datetime.utcnow().strftime("%Y%m%d")}.json"'
    }
    return Response(
        content=json.dumps(export_data, indent=2),
        media_type='application/json',
        headers=headers
    )


@router.get("/exports/scans/{scan_id}/findings.sarif")
async def export_findings_sarif(scan_id: int, db: Session = Depends(get_db)):
    """
    Export findings in SARIF format for CI/CD integration (GitHub, GitLab, etc.).

    SARIF (Static Analysis Results Interchange Format) is a standard format
    for the output of static analysis tools.
    """
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    findings = db.query(Finding).filter(Finding.scan_id == scan_id).all()

    # Map severity to SARIF levels
    severity_map = {
        'CRITICAL': 'error',
        'HIGH': 'error',
        'MEDIUM': 'warning',
        'LOW': 'note',
        'INFO': 'note'
    }

    # Build SARIF 2.1.0 structure
    sarif_output = {
        "version": "2.1.0",
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Icebreaker",
                        "version": "0.2.0",
                        "informationUri": "https://github.com/anthropics/icebreaker",
                        "rules": []
                    }
                },
                "results": [],
                "properties": {
                    "scan_id": scan.id,
                    "scan_name": scan.name or scan.run_id,
                    "scan_started": scan.started_at.isoformat(),
                    "scan_completed": scan.completed_at.isoformat() if scan.completed_at else None
                }
            }
        ]
    }

    # Build deduplicated rules from findings themselves
    seen_rules: set = set()
    for finding in findings:
        if finding.finding_id in seen_rules:
            continue
        seen_rules.add(finding.finding_id)
        details = finding.details or {}
        rule = {
            "id": finding.finding_id,
            "name": finding.title,
            "shortDescription": {"text": finding.title},
            "fullDescription": {"text": finding.description or finding.title},
            "help": {
                "text": finding.recommendation or "",
                "markdown": (
                    f"**Impact:**\n{finding.impact or ''}\n\n"
                    f"**Remediation:**\n{finding.recommendation or ''}"
                ),
            },
            "properties": {
                "tags": finding.tags or [],
                "precision": "high" if finding.severity in ("CRITICAL", "HIGH") else "medium",
            },
        }
        cwe = details.get("cwe_id")
        cvss = details.get("cvss3_base_score") or details.get("cvss_base_score")
        if cwe:
            rule["properties"]["cwe"] = cwe
        if cvss:
            rule["properties"]["cvss_score"] = cvss
        sarif_output["runs"][0]["tool"]["driver"]["rules"].append(rule)

    # Add results (actual findings)
    for finding in findings:
        if finding.false_positive:
            continue  # Skip false positives in SARIF export

        result = {
            "ruleId": finding.finding_id,
            "level": severity_map.get(finding.severity.upper(), 'warning'),
            "message": {
                "text": finding.title
            },
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": f"network://{finding.target}"
                        },
                        "region": {
                            "startLine": finding.port or 1,
                            "snippet": {
                                "text": f"Service on port {finding.port}" if finding.port else "Network finding"
                            }
                        }
                    }
                }
            ],
            "properties": {
                "confidence": finding.confidence,
                "risk_score": finding.risk_score,
                "status": finding.status,
                "tags": finding.tags if finding.tags else []
            }
        }

        if finding.recommendation:
            result["fixes"] = [
                {
                    "description": {
                        "text": finding.recommendation
                    }
                }
            ]

        sarif_output["runs"][0]["results"].append(result)

    # Return SARIF file
    headers = {
        'Content-Disposition': f'attachment; filename="findings-scan-{scan_id}-{datetime.utcnow().strftime("%Y%m%d")}.sarif"'
    }
    return Response(
        content=json.dumps(sarif_output, indent=2),
        media_type='application/json',
        headers=headers
    )


@router.get("/exports/scans/{scan_id}/findings.md")
async def export_findings_markdown(scan_id: int, db: Session = Depends(get_db)):
    """Export findings as Markdown for documentation."""
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    findings = db.query(Finding).filter(Finding.scan_id == scan_id).all()

    # Build Markdown content
    md_lines = []
    md_lines.append(f"# Security Findings - {scan.name or scan.run_id}")
    md_lines.append(f"\n**Scan ID:** {scan.run_id}")
    md_lines.append(f"**Started:** {scan.started_at.strftime('%Y-%m-%d %H:%M:%S UTC')}")
    if scan.completed_at:
        md_lines.append(f"**Completed:** {scan.completed_at.strftime('%Y-%m-%d %H:%M:%S UTC')}")
    md_lines.append(f"**Status:** {scan.status.value}")
    md_lines.append("\n---\n")

    # Group by severity
    from collections import defaultdict
    by_severity = defaultdict(list)
    for finding in findings:
        if not finding.false_positive:
            by_severity[finding.severity].append(finding)

    # Write findings by severity
    for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']:
        if severity in by_severity and by_severity[severity]:
            severity_emoji = {
                'CRITICAL': '🔴',
                'HIGH': '🟠',
                'MEDIUM': '🟡',
                'LOW': '🟢',
                'INFO': '🔵'
            }
            md_lines.append(f"\n## {severity_emoji.get(severity, '•')} {severity} Severity ({len(by_severity[severity])} findings)\n")

            for finding in by_severity[severity]:
                md_lines.append(f"\n### {finding.title}")
                md_lines.append(f"\n- **Target:** `{finding.target}`{f':{finding.port}' if finding.port else ''}")
                md_lines.append(f"- **Confidence:** {finding.confidence * 100:.0f}%")
                if finding.risk_score:
                    md_lines.append(f"- **Risk Score:** {finding.risk_score}")
                md_lines.append(f"- **Status:** {finding.status.replace('_', ' ').title()}")
                if finding.tags:
                    md_lines.append(f"- **Tags:** {', '.join(f'`{tag}`' for tag in finding.tags)}")

                if finding.template:
                    if finding.template.cwe_id:
                        md_lines.append(f"- **CWE:** {finding.template.cwe_id}")
                    if finding.template.owasp_2021:
                        md_lines.append(f"- **OWASP:** {finding.template.owasp_2021}")

                if finding.recommendation:
                    md_lines.append(f"\n**Recommendation:**\n{finding.recommendation}")

                md_lines.append("\n---")

    md_lines.append(f"\n\n*Exported on {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')} by Icebreaker*")

    # Return Markdown file
    md_content = '\n'.join(md_lines)
    headers = {
        'Content-Disposition': f'attachment; filename="findings-scan-{scan_id}-{datetime.utcnow().strftime("%Y%m%d")}.md"'
    }
    return Response(content=md_content, media_type='text/markdown', headers=headers)
