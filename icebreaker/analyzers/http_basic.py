from __future__ import annotations
import httpx
from typing import List
from icebreaker.core.models import RunContext, Service, Finding

import uuid as _uuid


class HTTPBasic:
    id = "http_basic"
    consumes = ["service:http", "service:https"]

    async def run(self, ctx: RunContext, service: Service) -> List[Finding]:
        f: list[Finding] = []
        meta = service.meta or {}
        server = meta.get("server", "")
        title = meta.get("title", "")

        # Generic HTTP info
        if server:
            f.append(Finding(
                id=f"http.server_header.{service.target}.{service.port}",
                title="Server header exposed",
                severity="INFO",
                target=service.target, port=service.port,
                tags=["http", "header"],
                details={"server": server},
                description="The HTTP Server header is exposed, revealing information about the web server software and potentially its version.",
                impact="Attackers can use this information to identify known vulnerabilities specific to the web server software and version being used.",
                recommendation="Configure the web server to remove or obscure the Server header. For Apache, use 'ServerTokens Prod' and 'ServerSignature Off'. For Nginx, use 'server_tokens off;'.",
                references=["CWE-200", "OWASP-A01:2021"]
            ))
        if service.name == "http" and not title:
            f.append(Finding(
                id=f"http.missing_title.{service.target}.{service.port}",
                title="Missing or empty page title",
                severity="INFO",
                target=service.target, port=service.port,
                tags=["http", "content"],
                description="The web page does not have a title or the title is empty.",
                impact="This may indicate a misconfigured or default installation, and could affect SEO and user experience.",
                recommendation="Ensure all web pages have descriptive titles that accurately reflect their content."
            ))

        # Redirect to TLS check (on port 80)
        if service.name == "http":
            status = meta.get("status", 0)
            location = (meta.get("location") or "").strip()
            if status in (301, 302, 307, 308) and location.lower().startswith("https://"):
                pass  # good
            else:
                f.append(Finding(
                    id=f"http.no_tls_redirect.{service.target}.{service.port}",
                    title="HTTP does not redirect to HTTPS",
                    severity="MEDIUM",
                    target=service.target, port=service.port,
                    tags=["http", "tls", "redirect"],
                    details={"status": str(status), "location": location},
                    description="The HTTP service does not automatically redirect to HTTPS. Users accessing the site over HTTP will transmit data in cleartext.",
                    impact="Without HTTPS redirection, users may inadvertently send sensitive information (credentials, session tokens, personal data) over an unencrypted connection, exposing it to man-in-the-middle attacks and eavesdropping.",
                    recommendation="Configure the web server to redirect all HTTP traffic to HTTPS using a 301 (permanent) or 308 (permanent, preserves method) redirect. Example for Apache: 'Redirect permanent / https://yourdomain.com/'. For Nginx: 'return 301 https://$host$request_uri;'",
                    references=["CWE-319", "OWASP-A02:2021"]
                ))

        # HSTS check (on port 443)
        if service.name == "https":
            hsts = (meta.get("hsts") or "").strip()
            if not hsts:
                f.append(Finding(
                    id=f"https.missing_hsts.{service.target}.{service.port}",
                    title="HSTS header missing on HTTPS",
                    severity="LOW",
                    target=service.target, port=service.port,
                    tags=["https", "hsts"],
                    description="The Strict-Transport-Security (HSTS) HTTP header is not set on this HTTPS service. HSTS instructs browsers to only access the site over HTTPS, even if the user types 'http://' or clicks an HTTP link.",
                    impact="Without HSTS, users remain vulnerable to protocol downgrade attacks and cookie hijacking. Attackers can intercept the initial HTTP request before redirection to HTTPS, or strip TLS from the connection.",
                    recommendation="Add the 'Strict-Transport-Security' header to all HTTPS responses. Recommended value: 'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload'. Consider submitting to the HSTS preload list.",
                    references=["CWE-319", "OWASP-A02:2021", "RFC-6797"]
                ))

        # HTTP Methods Allowed — mirrors Nessus "HTTP Methods Allowed (per directory)"
        await self._check_http_methods(service, f)

        # No 404 check — mirrors Nessus "Web Server No 404 Error Code Check"
        await self._check_no_404(service, f)

        return f

    async def _check_http_methods(self, service: Service, findings: list) -> None:
        """Check which HTTP methods are allowed via OPTIONS request."""
        scheme = "https" if service.name == "https" else "http"
        base = f"{scheme}://{service.target}"
        if (scheme == "http" and service.port != 80) or (scheme == "https" and service.port != 443):
            base += f":{service.port}"
        try:
            async with httpx.AsyncClient(timeout=3.0, verify=False, follow_redirects=False) as client:
                r = await client.options(f"{base}/")
                allow = r.headers.get("allow", r.headers.get("Allow", ""))
                methods = [m.strip().upper() for m in allow.split(",") if m.strip()]
                dangerous = [m for m in methods if m in ("PUT", "DELETE", "TRACE", "CONNECT", "PROPFIND", "PROPPATCH", "MKCOL", "COPY", "MOVE", "LOCK", "UNLOCK")]
                if methods:
                    findings.append(Finding(
                        id=f"http.methods.{service.target}.{service.port}",
                        title="HTTP Methods Allowed (per directory)",
                        severity="MEDIUM" if dangerous else "INFO",
                        target=service.target,
                        port=service.port,
                        tags=["http", "methods"],
                        description=f"The web server advertises the following HTTP methods: {', '.join(methods)}.",
                        details={"allowed_methods": methods, "dangerous_methods": dangerous},
                        recommendation=(
                            f"Disable dangerous HTTP methods ({', '.join(dangerous)}) unless explicitly required."
                            if dangerous else "Review the list of allowed methods and disable any that are not required."
                        ),
                        references=["CWE-16", "OWASP-A05:2021"] if dangerous else [],
                    ))
        except Exception:
            pass

    async def _check_no_404(self, service: Service, findings: list) -> None:
        """
        Check if the server returns a non-404 response for a random URL.
        Mirrors Nessus plugin 'Web Server No 404 Error Code Check'.
        """
        scheme = "https" if service.name == "https" else "http"
        base = f"{scheme}://{service.target}"
        if (scheme == "http" and service.port != 80) or (scheme == "https" and service.port != 443):
            base += f":{service.port}"
        random_path = f"/icebreaker-nonexistent-{_uuid.uuid4().hex[:8]}"
        try:
            async with httpx.AsyncClient(timeout=3.0, verify=False, follow_redirects=False) as client:
                r = await client.get(f"{base}{random_path}")
                if r.status_code == 200:
                    findings.append(Finding(
                        id=f"http.no_404.{service.target}.{service.port}",
                        title="Web Server No 404 Error Code Check",
                        severity="INFO",
                        target=service.target,
                        port=service.port,
                        tags=["http", "error-handling"],
                        description=(
                            f"The web server returns HTTP 200 for non-existent resources "
                            f"(tested: {random_path}). This 'soft 404' behaviour can interfere "
                            "with vulnerability scanners and indicates custom error handling."
                        ),
                        details={"test_path": random_path, "status_code": r.status_code},
                        recommendation=(
                            "Configure the web server to return proper 404 responses for "
                            "missing resources. For Apache, ensure ErrorDocument directives "
                            "use 404 status. For custom applications, return HTTP 404 when "
                            "a resource does not exist."
                        ),
                    ))
        except Exception:
            pass
