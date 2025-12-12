"""
Simple authentication for Icebreaker API.

Supports API key authentication for securing the web interface.
"""
from __future__ import annotations
import os
import secrets
from fastapi import Security, HTTPException, status
from fastapi.security import APIKeyHeader
from typing import Optional

# API key header
api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)

# Get API key from environment or generate one
API_KEY = os.getenv("ICEBREAKER_API_KEY")

# If no API key is set, authentication is disabled
AUTH_ENABLED = bool(API_KEY)


def generate_api_key() -> str:
    """Generate a secure random API key."""
    return secrets.token_urlsafe(32)


async def get_api_key(api_key: Optional[str] = Security(api_key_header)) -> Optional[str]:
    """
    Dependency to verify API key.

    Args:
        api_key: API key from request header

    Returns:
        API key if valid

    Raises:
        HTTPException: If authentication is enabled and key is invalid
    """
    # If auth is not enabled, allow all requests
    if not AUTH_ENABLED:
        return None

    # Check if API key is provided and valid
    if not api_key or api_key != API_KEY:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing API key",
            headers={"WWW-Authenticate": "ApiKey"},
        )

    return api_key


# Optional dependency - doesn't raise error if not authenticated
api_key_optional = APIKeyHeader(name="X-API-Key", auto_error=False)
