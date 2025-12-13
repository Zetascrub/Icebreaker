"""
Report generator for creating professional scan reports.
"""
from __future__ import annotations
from typing import Dict, Any, List
from datetime import datetime
from collections import defaultdict
from jinja2 import Environment, FileSystemLoader
import os
from sqlalchemy.orm import Session

from icebreaker.db.models import Scan, Finding, Service, Target


class ReportGenerator:
    """Generates professional reports from scan data."""

    def __init__(self, db: Session):
        self.db = db
        # Setup Jinja2 environment for report templates
        template_dir = os.path.join(
            os.path.dirname(os.path.dirname(__file__)),
            'web',
            'templates',
            'reports'
        )
        self.jinja_env = Environment(loader=FileSystemLoader(template_dir))

    def generate_executive_report(self, scan_id: int) -> str:
        """
        Generate an executive summary report (high-level, for management).

        Args:
            scan_id: Scan ID to generate report for

        Returns:
            HTML string of the report
        """
        data = self._gather_scan_data(scan_id)
        if data.get('error'):
            return f"<html><body><h1>Error</h1><p>{data['error']}</p></body></html>"

        template = self.jinja_env.get_template('executive_summary.html')
        return template.render(**data)

    def generate_technical_report(self, scan_id: int) -> str:
        """
        Generate a detailed technical report (comprehensive, for engineers).

        Args:
            scan_id: Scan ID to generate report for

        Returns:
            HTML string of the report
        """
        data = self._gather_scan_data(scan_id)
        if data.get('error'):
            return f"<html><body><h1>Error</h1><p>{data['error']}</p></body></html>"

        template = self.jinja_env.get_template('technical_report.html')
        return template.render(**data)

    def _gather_scan_data(self, scan_id: int) -> Dict[str, Any]:
        """Gather all data needed for report generation."""
        # Get scan
        scan = self.db.query(Scan).filter(Scan.id == scan_id).first()
        if not scan:
            return {'error': 'Scan not found'}

        # Get findings
        findings = self.db.query(Finding).filter(
            Finding.scan_id == scan_id
        ).all()

        # Get services
        services = self.db.query(Service).filter(
            Service.scan_id == scan_id
        ).all()

        # Get targets
        targets = self.db.query(Target).filter(
            Target.scan_id == scan_id
        ).all()

        # Calculate statistics
        severity_counts = defaultdict(int)
        status_counts = defaultdict(int)
        false_positives = 0

        for finding in findings:
            if finding.false_positive:
                false_positives += 1
            else:
                severity_counts[finding.severity] += 1
                status_counts[finding.status] += 1

        # Calculate risk score
        risk_weights = {'CRITICAL': 10, 'HIGH': 7, 'MEDIUM': 4, 'LOW': 2, 'INFO': 1}
        total_risk_score = sum(
            severity_counts.get(sev, 0) * weight
            for sev, weight in risk_weights.items()
        )

        # Group findings by severity
        findings_by_severity = defaultdict(list)
        for finding in findings:
            if not finding.false_positive:
                findings_by_severity[finding.severity].append(finding)

        # Group services by host
        services_by_host = defaultdict(list)
        for service in services:
            services_by_host[service.target].append(service)

        # Alive hosts
        alive_hosts = [t for t in targets if t.is_alive]
        dead_hosts = [t for t in targets if t.is_alive == False]

        # Top vulnerable hosts
        host_findings = defaultdict(list)
        for finding in findings:
            if not finding.false_positive:
                host_findings[finding.target].append(finding)

        top_hosts = sorted(
            host_findings.items(),
            key=lambda x: len(x[1]),
            reverse=True
        )[:10]

        # Most common finding types
        finding_type_counts = defaultdict(int)
        for finding in findings:
            if not finding.false_positive:
                finding_type_counts[finding.finding_id] += 1

        top_finding_types = sorted(
            finding_type_counts.items(),
            key=lambda x: x[1],
            reverse=True
        )[:10]

        return {
            'scan': scan,
            'generated_at': datetime.utcnow(),
            'summary': {
                'total_targets': len(targets),
                'alive_hosts': len(alive_hosts),
                'dead_hosts': len(dead_hosts),
                'total_services': len(services),
                'total_findings': len(findings) - false_positives,
                'false_positives': false_positives,
                'severity_counts': dict(severity_counts),
                'status_counts': dict(status_counts),
                'total_risk_score': total_risk_score,
            },
            'findings': findings,
            'findings_by_severity': dict(findings_by_severity),
            'services': services,
            'services_by_host': dict(services_by_host),
            'targets': targets,
            'alive_hosts': alive_hosts,
            'top_hosts': top_hosts,
            'top_finding_types': top_finding_types,
        }
