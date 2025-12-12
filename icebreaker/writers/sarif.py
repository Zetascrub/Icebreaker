from __future__ import annotations

import json
from pathlib import Path
from typing import List, Dict, Any

from icebreaker.core.models import RunContext, Service, Finding


class SARIFWriter:
    """
    SARIF (Static Analysis Results Interchange Format) writer.

    Outputs findings in SARIF v2.1.0 format for integration with:
    - GitHub Security
    - Azure DevOps
    - GitLab Security
    - Other SARIF-compatible tools
    """

    id = "sarif"

    def write(self, ctx: RunContext, services: List[Service], findings: List[Finding]) -> None:
        """Write findings in SARIF format."""
        path = Path(ctx.out_dir) / "results.sarif"

        # Map severity to SARIF level
        severity_map = {
            "CRITICAL": "error",
            "HIGH": "error",
            "MEDIUM": "warning",
            "LOW": "note",
            "INFO": "none",
        }

        # Build SARIF results
        results = []
        for finding in findings:
            # Build result object
            result = {
                "ruleId": finding.id.split('.')[0] if '.' in finding.id else finding.id,
                "level": severity_map.get(finding.severity.upper(), "warning"),
                "message": {
                    "text": finding.title
                },
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": f"{finding.target}:{finding.port or 0}"
                            },
                            "region": {
                                "startLine": 1,
                                "startColumn": 1
                            }
                        }
                    }
                ],
                "properties": {
                    "tags": finding.tags,
                    "severity": finding.severity,
                    "confidence": finding.confidence,
                    "risk_score": finding.risk_score,
                }
            }

            # Add details if present
            if finding.details:
                result["properties"]["details"] = finding.details

            # Add recommendation if present
            if finding.recommendation:
                result["message"]["markdown"] = f"{finding.title}\n\n**Recommendation:** {finding.recommendation}"

            results.append(result)

        # Build SARIF document
        sarif = {
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "Icebreaker",
                            "version": "0.2.0",
                            "informationUri": "https://github.com/yourusername/icebreaker",
                            "rules": self._build_rules(findings)
                        }
                    },
                    "results": results,
                    "properties": {
                        "run_id": ctx.run_id,
                        "preset": ctx.preset,
                        "started_at": ctx.started_at.isoformat()
                    }
                }
            ]
        }

        # Write SARIF file
        path.write_text(json.dumps(sarif, indent=2), encoding="utf-8")

    def _build_rules(self, findings: List[Finding]) -> List[Dict[str, Any]]:
        """Build SARIF rules from findings."""
        rules_map = {}

        for finding in findings:
            rule_id = finding.id.split('.')[0] if '.' in finding.id else finding.id

            if rule_id not in rules_map:
                rules_map[rule_id] = {
                    "id": rule_id,
                    "name": rule_id.replace('_', ' ').title(),
                    "shortDescription": {
                        "text": finding.title
                    },
                    "fullDescription": {
                        "text": finding.title
                    },
                    "helpUri": f"https://github.com/yourusername/icebreaker/docs/{rule_id}",
                    "properties": {
                        "tags": list(set(finding.tags))
                    }
                }

        return list(rules_map.values())
