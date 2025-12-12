from __future__ import annotations
from typing import List
from icebreaker.core.models import RunContext, Service, Finding


class SecurityHeaders:
    """
    Analyzer for security-related HTTP headers.

    Checks for:
    - Content-Security-Policy (CSP)
    - X-Frame-Options
    - X-Content-Type-Options
    - X-XSS-Protection
    - Referrer-Policy
    - Permissions-Policy
    - Strict-Transport-Security (HSTS)
    """

    id = "security_headers"
    consumes = ["service:http", "service:https"]

    async def run(self, ctx: RunContext, service: Service) -> List[Finding]:
        findings: List[Finding] = []
        meta = service.meta or {}

        # Check for Content-Security-Policy
        csp = meta.get("content-security-policy", "").strip()
        if not csp:
            findings.append(Finding(
                id=f"sec_headers.missing_csp.{service.target}.{service.port}",
                title="Missing Content-Security-Policy header",
                severity="MEDIUM",
                target=service.target,
                port=service.port,
                tags=["http", "security-headers", "csp"],
                details={"recommendation": "Add CSP header to prevent XSS attacks"}
            ))

        # Check for X-Frame-Options
        x_frame = meta.get("x-frame-options", "").strip()
        if not x_frame:
            findings.append(Finding(
                id=f"sec_headers.missing_x_frame.{service.target}.{service.port}",
                title="Missing X-Frame-Options header",
                severity="MEDIUM",
                target=service.target,
                port=service.port,
                tags=["http", "security-headers", "clickjacking"],
                details={"recommendation": "Add 'X-Frame-Options: DENY' or 'SAMEORIGIN'"}
            ))

        # Check for X-Content-Type-Options
        x_content_type = meta.get("x-content-type-options", "").strip()
        if not x_content_type:
            findings.append(Finding(
                id=f"sec_headers.missing_x_content_type.{service.target}.{service.port}",
                title="Missing X-Content-Type-Options header",
                severity="LOW",
                target=service.target,
                port=service.port,
                tags=["http", "security-headers", "mime-sniffing"],
                details={"recommendation": "Add 'X-Content-Type-Options: nosniff'"}
            ))

        # Check for Referrer-Policy
        referrer_policy = meta.get("referrer-policy", "").strip()
        if not referrer_policy:
            findings.append(Finding(
                id=f"sec_headers.missing_referrer_policy.{service.target}.{service.port}",
                title="Missing Referrer-Policy header",
                severity="LOW",
                target=service.target,
                port=service.port,
                tags=["http", "security-headers", "privacy"],
                details={"recommendation": "Add 'Referrer-Policy: no-referrer' or 'strict-origin-when-cross-origin'"}
            ))

        # Check for Permissions-Policy (formerly Feature-Policy)
        permissions_policy = meta.get("permissions-policy", "").strip()
        feature_policy = meta.get("feature-policy", "").strip()
        if not permissions_policy and not feature_policy:
            findings.append(Finding(
                id=f"sec_headers.missing_permissions_policy.{service.target}.{service.port}",
                title="Missing Permissions-Policy header",
                severity="LOW",
                target=service.target,
                port=service.port,
                tags=["http", "security-headers", "permissions"],
                details={"recommendation": "Add Permissions-Policy to control browser features"}
            ))

        # Check for deprecated X-XSS-Protection
        x_xss = meta.get("x-xss-protection", "").strip()
        if x_xss:
            findings.append(Finding(
                id=f"sec_headers.deprecated_x_xss.{service.target}.{service.port}",
                title="Deprecated X-XSS-Protection header present",
                severity="INFO",
                target=service.target,
                port=service.port,
                tags=["http", "security-headers", "deprecated"],
                details={
                    "value": x_xss,
                    "recommendation": "Remove X-XSS-Protection and use CSP instead"
                }
            ))

        # Check for weak CSP if present
        if csp and ("unsafe-inline" in csp or "unsafe-eval" in csp):
            findings.append(Finding(
                id=f"sec_headers.weak_csp.{service.target}.{service.port}",
                title="Weak Content-Security-Policy detected",
                severity="MEDIUM",
                target=service.target,
                port=service.port,
                tags=["http", "security-headers", "csp"],
                details={
                    "csp": csp,
                    "issue": "CSP contains unsafe-inline or unsafe-eval"
                }
            ))

        return findings
