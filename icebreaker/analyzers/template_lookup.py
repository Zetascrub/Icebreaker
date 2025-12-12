"""
Template lookup helper for analyzers.

Provides quick access to finding template IDs for linking analyzer findings
to standardized templates with descriptions, impact, and remediation.
"""
from typing import Optional, Dict
from icebreaker.db.database import SessionLocal
from icebreaker.db.models import FindingTemplate


# Cache for template IDs to avoid repeated database queries
_template_cache: Dict[str, int] = {}


def get_template_id(finding_id: str) -> Optional[int]:
    """
    Get the database ID for a finding template by its finding_id.

    Args:
        finding_id: The template finding_id (e.g., "ICEBREAKER-001")

    Returns:
        Template database ID or None if not found
    """
    # Check cache first
    if finding_id in _template_cache:
        return _template_cache[finding_id]

    # Query database
    try:
        db = SessionLocal()
        try:
            template = db.query(FindingTemplate).filter(
                FindingTemplate.finding_id == finding_id
            ).first()

            if template:
                _template_cache[finding_id] = template.id
                return template.id
        finally:
            db.close()
    except Exception:
        # If database query fails, return None (finding will be created without template)
        pass

    return None


def clear_cache():
    """Clear the template cache. Useful for testing or after template updates."""
    global _template_cache
    _template_cache = {}
