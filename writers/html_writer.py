from __future__ import annotations

from pathlib import Path
from typing import List, Dict
from datetime import datetime

from icebreaker.core.models import RunContext, Service, Finding


class HTMLWriter:
    """
    HTML report writer with interactive filtering.

    Generates a standalone HTML report with:
    - Executive summary
    - Risk distribution charts
    - Filterable findings table
    - Service details
    """

    id = "html"

    def write(self, ctx: RunContext, services: List[Service], findings: List[Finding]) -> None:
        """Write HTML report."""
        path = Path(ctx.out_dir) / "report.html"

        # Calculate statistics
        total_findings = len(findings)
        severity_counts = self._count_by_severity(findings)
        risk_distribution = self._calculate_risk_distribution(findings)

        # Build HTML
        html = self._build_html(ctx, services, findings, severity_counts, risk_distribution)

        # Write file
        path.write_text(html, encoding="utf-8")

    def _count_by_severity(self, findings: List[Finding]) -> Dict[str, int]:
        """Count findings by severity."""
        counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for f in findings:
            counts[f.severity.upper()] = counts.get(f.severity.upper(), 0) + 1
        return counts

    def _calculate_risk_distribution(self, findings: List[Finding]) -> Dict[str, int]:
        """Calculate risk score distribution."""
        distribution = {"9-10": 0, "7-8": 0, "5-6": 0, "3-4": 0, "0-2": 0}
        for f in findings:
            score = f.risk_score or 0.0
            if score >= 9:
                distribution["9-10"] += 1
            elif score >= 7:
                distribution["7-8"] += 1
            elif score >= 5:
                distribution["5-6"] += 1
            elif score >= 3:
                distribution["3-4"] += 1
            else:
                distribution["0-2"] += 1
        return distribution

    def _build_html(
        self,
        ctx: RunContext,
        services: List[Service],
        findings: List[Finding],
        severity_counts: Dict[str, int],
        risk_distribution: Dict[str, int]
    ) -> str:
        """Build full HTML report."""
        findings_rows = "\n".join(self._build_finding_row(f) for f in findings)

        return f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Icebreaker Security Scan Report - {ctx.run_id}</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: #f5f5f5;
            padding: 20px;
        }}
        .container {{ max-width: 1400px; margin: 0 auto; }}
        .header {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px;
            border-radius: 8px;
            margin-bottom: 20px;
        }}
        .header h1 {{ font-size: 32px; margin-bottom: 10px; }}
        .header p {{ opacity: 0.9; }}
        .stats {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin-bottom: 20px;
        }}
        .stat-card {{
            background: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}
        .stat-card .label {{ color: #666; font-size: 14px; margin-bottom: 5px; }}
        .stat-card .value {{ font-size: 32px; font-weight: bold; }}
        .critical {{ color: #dc2626; }}
        .high {{ color: #ea580c; }}
        .medium {{ color: #f59e0b; }}
        .low {{ color: #3b82f6; }}
        .info {{ color: #6b7280; }}
        .findings {{
            background: white;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            overflow: hidden;
        }}
        .findings-header {{
            padding: 20px;
            border-bottom: 1px solid #e5e7eb;
        }}
        .findings-header h2 {{ margin-bottom: 15px; }}
        .filters {{
            display: flex;
            gap: 10px;
            flex-wrap: wrap;
        }}
        .filters input, .filters select {{
            padding: 8px 12px;
            border: 1px solid #d1d5db;
            border-radius: 4px;
            font-size: 14px;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
        }}
        th, td {{
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #e5e7eb;
        }}
        th {{
            background: #f9fafb;
            font-weight: 600;
            color: #374151;
        }}
        tr:hover {{ background: #f9fafb; }}
        .severity-badge {{
            display: inline-block;
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 12px;
            font-weight: 600;
            text-transform: uppercase;
        }}
        .badge-critical {{ background: #fee2e2; color: #dc2626; }}
        .badge-high {{ background: #ffedd5; color: #ea580c; }}
        .badge-medium {{ background: #fef3c7; color: #f59e0b; }}
        .badge-low {{ background: #dbeafe; color: #3b82f6; }}
        .badge-info {{ background: #f3f4f6; color: #6b7280; }}
        .tags {{ display: flex; gap: 4px; flex-wrap: wrap; }}
        .tag {{
            background: #e5e7eb;
            padding: 2px 6px;
            border-radius: 3px;
            font-size: 11px;
            color: #374151;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🧊 Icebreaker Security Scan Report</h1>
            <p>Run ID: {ctx.run_id} | Started: {ctx.started_at.strftime('%Y-%m-%d %H:%M:%S UTC')} | Preset: {ctx.preset}</p>
        </div>

        <div class="stats">
            <div class="stat-card">
                <div class="label">Total Findings</div>
                <div class="value">{len(findings)}</div>
            </div>
            <div class="stat-card">
                <div class="label">Critical</div>
                <div class="value critical">{severity_counts.get('CRITICAL', 0)}</div>
            </div>
            <div class="stat-card">
                <div class="label">High</div>
                <div class="value high">{severity_counts.get('HIGH', 0)}</div>
            </div>
            <div class="stat-card">
                <div class="label">Medium</div>
                <div class="value medium">{severity_counts.get('MEDIUM', 0)}</div>
            </div>
            <div class="stat-card">
                <div class="label">Low</div>
                <div class="value low">{severity_counts.get('LOW', 0)}</div>
            </div>
            <div class="stat-card">
                <div class="label">Targets Scanned</div>
                <div class="value">{len(services)}</div>
            </div>
        </div>

        <div class="findings">
            <div class="findings-header">
                <h2>Findings</h2>
                <div class="filters">
                    <input type="text" id="searchInput" placeholder="Search..." onkeyup="filterTable()">
                    <select id="severityFilter" onchange="filterTable()">
                        <option value="">All Severities</option>
                        <option value="CRITICAL">Critical</option>
                        <option value="HIGH">High</option>
                        <option value="MEDIUM">Medium</option>
                        <option value="LOW">Low</option>
                        <option value="INFO">Info</option>
                    </select>
                </div>
            </div>
            <table id="findingsTable">
                <thead>
                    <tr>
                        <th>Severity</th>
                        <th>Risk</th>
                        <th>Target</th>
                        <th>Port</th>
                        <th>Title</th>
                        <th>Tags</th>
                    </tr>
                </thead>
                <tbody>
                    {findings_rows}
                </tbody>
            </table>
        </div>
    </div>

    <script>
        function filterTable() {{
            const searchValue = document.getElementById('searchInput').value.toLowerCase();
            const severityValue = document.getElementById('severityFilter').value;
            const table = document.getElementById('findingsTable');
            const rows = table.getElementsByTagName('tr');

            for (let i = 1; i < rows.length; i++) {{
                const row = rows[i];
                const text = row.textContent.toLowerCase();
                const severity = row.getAttribute('data-severity');

                const matchesSearch = searchValue === '' || text.includes(searchValue);
                const matchesSeverity = severityValue === '' || severity === severityValue;

                row.style.display = (matchesSearch && matchesSeverity) ? '' : 'none';
            }}
        }}
    </script>
</body>
</html>"""

    def _build_finding_row(self, finding: Finding) -> str:
        """Build HTML table row for a finding."""
        severity_class = finding.severity.lower()
        badge_class = f"badge-{severity_class}"
        tags_html = "".join(f'<span class="tag">{tag}</span>' for tag in finding.tags[:5])

        return f"""<tr data-severity="{finding.severity.upper()}">
            <td><span class="severity-badge {badge_class}">{finding.severity}</span></td>
            <td>{finding.risk_score or 0:.1f}</td>
            <td>{finding.target}</td>
            <td>{finding.port or '-'}</td>
            <td>{finding.title}</td>
            <td><div class="tags">{tags_html}</div></td>
        </tr>"""
