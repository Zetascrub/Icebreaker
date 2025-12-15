"""
CSRF Protection for FastAPI.

Provides CSRF token generation and validation for forms and AJAX requests.
"""
from __future__ import annotations
import secrets
from typing import Optional
from fastapi import Request, HTTPException, status
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response
from itsdangerous import URLSafeTimedSerializer, BadSignature


class CSRFProtection:
    """CSRF token generator and validator."""

    def __init__(self, secret_key: str, token_name: str = "csrf_token", cookie_name: str = "csrf_token"):
        """
        Initialize CSRF protection.

        Args:
            secret_key: Secret key for signing tokens
            token_name: Name of the CSRF token field
            cookie_name: Name of the CSRF cookie
        """
        self.secret_key = secret_key
        self.token_name = token_name
        self.cookie_name = cookie_name
        self.serializer = URLSafeTimedSerializer(secret_key)

    def generate_token(self) -> str:
        """Generate a new CSRF token."""
        return self.serializer.dumps(secrets.token_urlsafe(32))

    def validate_token(self, token: str, max_age: int = 3600) -> bool:
        """
        Validate a CSRF token.

        Args:
            token: Token to validate
            max_age: Maximum age of token in seconds (default 1 hour)

        Returns:
            True if valid, False otherwise
        """
        try:
            self.serializer.loads(token, max_age=max_age)
            return True
        except BadSignature:
            return False


class CSRFMiddleware(BaseHTTPMiddleware):
    """
    CSRF Protection Middleware.

    Protects state-changing operations (POST, PUT, DELETE, PATCH) from CSRF attacks.
    """

    def __init__(self, app, secret_key: str, exempt_paths: Optional[list[str]] = None):
        """
        Initialize CSRF middleware.

        Args:
            app: FastAPI application
            secret_key: Secret key for signing tokens
            exempt_paths: List of paths to exempt from CSRF protection (e.g., ["/api/webhooks"])
        """
        super().__init__(app)
        self.csrf = CSRFProtection(secret_key)
        self.exempt_paths = exempt_paths or []
        # Safe methods don't need CSRF protection
        self.safe_methods = {"GET", "HEAD", "OPTIONS", "TRACE"}

    async def dispatch(self, request: Request, call_next):
        """Process request with CSRF protection."""
        # Skip CSRF for safe methods
        if request.method in self.safe_methods:
            response = await call_next(request)
            # Set CSRF cookie for GET requests if not present
            if request.method == "GET" and self.csrf.cookie_name not in request.cookies:
                token = self.csrf.generate_token()
                response.set_cookie(
                    key=self.csrf.cookie_name,
                    value=token,
                    httponly=True,
                    samesite="lax",
                    secure=request.url.scheme == "https"
                )
            return response

        # Check if path is exempt
        if any(request.url.path.startswith(path) for path in self.exempt_paths):
            return await call_next(request)

        # Validate CSRF token for state-changing operations
        cookie_token = request.cookies.get(self.csrf.cookie_name)
        if not cookie_token:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="CSRF cookie not found. Refresh the page and try again."
            )

        # Get token from header (AJAX) or form data
        header_token = request.headers.get("X-CSRF-Token")
        form_token = None

        # Try to get form token for form submissions
        if request.headers.get("content-type", "").startswith("application/x-www-form-urlencoded") or \
           request.headers.get("content-type", "").startswith("multipart/form-data"):
            try:
                form = await request.form()
                form_token = form.get(self.csrf.token_name)
            except Exception:
                pass

        # Use header token or form token
        request_token = header_token or form_token

        if not request_token:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="CSRF token not found in request. Include X-CSRF-Token header or csrf_token form field."
            )

        # Validate token
        if not self.csrf.validate_token(request_token):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Invalid or expired CSRF token. Refresh the page and try again."
            )

        # Token is valid, proceed with request
        response = await call_next(request)
        return response


def get_csrf_token(request: Request) -> str:
    """
    Get CSRF token for templates.

    Usage in Jinja2 template:
        <input type="hidden" name="csrf_token" value="{{ csrf_token }}">

    Args:
        request: FastAPI Request object

    Returns:
        CSRF token string
    """
    # Token should be in cookie
    token = request.cookies.get("csrf_token")
    if not token:
        # Generate new token if not present
        csrf = CSRFProtection(request.app.state.csrf_secret)
        token = csrf.generate_token()
    return token
