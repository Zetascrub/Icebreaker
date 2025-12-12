import pytest
from icebreaker.core.risk_scoring import calculate_risk_score, prioritize_findings
from icebreaker.core.models import Finding


def test_calculate_risk_score_critical():
    """Test risk score calculation for critical findings."""
    score = calculate_risk_score("CRITICAL", confidence=1.0)
    assert score == 9.0


def test_calculate_risk_score_high():
    """Test risk score calculation for high severity."""
    score = calculate_risk_score("HIGH", confidence=1.0)
    assert score == 7.0


def test_calculate_risk_score_medium():
    """Test risk score calculation for medium severity."""
    score = calculate_risk_score("MEDIUM", confidence=1.0)
    assert score == 5.0


def test_calculate_risk_score_with_confidence():
    """Test risk score with varying confidence levels."""
    score_full = calculate_risk_score("HIGH", confidence=1.0)
    score_half = calculate_risk_score("HIGH", confidence=0.5)

    assert score_full == 7.0
    assert score_half == 3.5


def test_calculate_risk_score_bounds():
    """Test that risk scores stay within bounds."""
    score = calculate_risk_score("CRITICAL", confidence=2.0)  # over 1.0
    assert score <= 10.0

    score = calculate_risk_score("INFO", confidence=0.0)
    assert score >= 0.0


def test_prioritize_findings():
    """Test that findings are prioritized correctly."""
    findings = [
        Finding(
            id="1", title="Low severity", severity="LOW",
            target="example.com", confidence=1.0
        ),
        Finding(
            id="2", title="Critical severity", severity="CRITICAL",
            target="example.com", confidence=1.0
        ),
        Finding(
            id="3", title="Medium severity", severity="MEDIUM",
            target="example.com", confidence=1.0
        ),
    ]

    prioritized = prioritize_findings(findings)

    # Critical should be first
    assert prioritized[0].severity == "CRITICAL"
    # Medium should be second
    assert prioritized[1].severity == "MEDIUM"
    # Low should be last
    assert prioritized[2].severity == "LOW"


def test_prioritize_with_confidence():
    """Test prioritization considering confidence."""
    findings = [
        Finding(
            id="1", title="High but low confidence", severity="HIGH",
            target="example.com", confidence=0.3
        ),
        Finding(
            id="2", title="Medium but high confidence", severity="MEDIUM",
            target="example.com", confidence=1.0
        ),
    ]

    prioritized = prioritize_findings(findings)

    # Medium with high confidence should rank higher than high with low confidence
    assert prioritized[0].id == "2"  # Medium * 1.0 = 5.0
    assert prioritized[1].id == "1"  # High * 0.3 = 2.1
