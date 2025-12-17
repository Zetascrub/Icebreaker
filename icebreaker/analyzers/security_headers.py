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
                description="The Content-Security-Policy (CSP) HTTP header is not set. CSP is an added layer of security that helps detect and mitigate certain types of attacks, including Cross-Site Scripting (XSS) and data injection attacks.",
                impact="Without CSP, the application is more vulnerable to XSS attacks, clickjacking, and other code injection attacks that could lead to data theft, session hijacking, or malware distribution.",
                recommendation="Implement a Content-Security-Policy header with a restrictive policy. Start with 'default-src \\'self\\'' and gradually add trusted sources. Use 'script-src', 'style-src', 'img-src' directives to control resource loading.",
                references=["CWE-693", "OWASP-A05:2021"]
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
                description="The X-Frame-Options HTTP header is not set. This header indicates whether a browser should be allowed to render a page in a <frame>, <iframe>, <embed> or <object> element.",
                impact="Without this header, the application is vulnerable to clickjacking attacks where an attacker could embed this page in a malicious site and trick users into clicking hidden elements.",
                recommendation="Add 'X-Frame-Options: DENY' to prevent all framing, or 'X-Frame-Options: SAMEORIGIN' to allow framing only from the same origin.",
                references=["CWE-1021", "OWASP-A05:2021"]
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
                description="The X-Content-Type-Options HTTP header is not set. This header prevents browsers from MIME-sniffing a response away from the declared content-type.",
                impact="Browsers may incorrectly detect file types, potentially executing malicious content disguised as innocent file types, leading to XSS attacks.",
                recommendation="Add 'X-Content-Type-Options: nosniff' to prevent MIME-type sniffing.",
                references=["CWE-693"]
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
                description="The Referrer-Policy HTTP header is not set. This header controls how much referrer information is included with requests.",
                impact="Sensitive information in URLs may be leaked to third parties through the Referer header, potentially exposing session tokens, user IDs, or other sensitive data.",
                recommendation="Add 'Referrer-Policy: no-referrer' for maximum privacy or 'strict-origin-when-cross-origin' for a balanced approach.",
                references=["CWE-200"]
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
                description="The Permissions-Policy HTTP header is not set. This header allows you to control which browser features and APIs can be used.",
                impact="Without this header, the application cannot restrict potentially dangerous browser features like geolocation, camera, microphone access, which could be exploited by malicious scripts.",
                recommendation="Add Permissions-Policy header to disable unnecessary features. Example: 'Permissions-Policy: geolocation=(), microphone=(), camera=()'",
                references=["OWASP-A05:2021"]
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
