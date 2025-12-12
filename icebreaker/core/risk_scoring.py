from __future__ import annotations

from typing import List
from icebreaker.core.models import Finding


# Severity to base score mapping (CVSS-like)
SEVERITY_SCORES = {
    "CRITICAL": 9.0,
    "HIGH": 7.0,
    "MEDIUM": 5.0,
    "LOW": 3.0,
    "INFO": 1.0,
}


def calculate_risk_score(severity: str, confidence: float = 1.0) -> float:
    """
    Calculate risk score for a finding.

    Risk Score = Base Score (from severity) × Confidence

    Args:
        severity: Severity level (CRITICAL, HIGH, MEDIUM, LOW, INFO)
        confidence: Confidence level (0.0 to 1.0)

    Returns:
        Risk score (0.0 to 10.0)
    """
    base_score = SEVERITY_SCORES.get(severity.upper(), 1.0)
    risk = base_score * confidence
    return round(min(10.0, max(0.0, risk)), 2)


def enrich_finding_with_risk(finding: Finding) -> Finding:
    """
    Enrich a finding with calculated risk score if not already set.

    Args:
        finding: Finding to enrich

    Returns:
        Enriched finding
    """
    if finding.risk_score is None:
        finding.risk_score = calculate_risk_score(finding.severity, finding.confidence)
    return finding


def prioritize_findings(findings: List[Finding]) -> List[Finding]:
    """
    Sort findings by risk score (highest first).

    Args:
        findings: List of findings to prioritize

    Returns:
        Sorted list of findings
    """
    # Enrich all findings with risk scores
    enriched = [enrich_finding_with_risk(f) for f in findings]

    # Sort by risk score (descending), then by severity, then by target
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}

    return sorted(
        enriched,
        key=lambda f: (
            -(f.risk_score or 0.0),
            severity_order.get(f.severity.upper(), 9),
            f.target,
            f.port or 0
        )
    )
