from __future__ import annotations
from typing import List
from icebreaker.core.models import RunContext, Service, Finding


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
                    id=f"http.no_tls_redirect.{service.target}.80",
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
                    id=f"https.missing_hsts.{service.target}.443",
                    title="HSTS header missing on HTTPS",
                    severity="LOW",
                    target=service.target, port=service.port,
                    tags=["https", "hsts"],
                    description="The Strict-Transport-Security (HSTS) HTTP header is not set on this HTTPS service. HSTS instructs browsers to only access the site over HTTPS, even if the user types 'http://' or clicks an HTTP link.",
                    impact="Without HSTS, users remain vulnerable to protocol downgrade attacks and cookie hijacking. Attackers can intercept the initial HTTP request before redirection to HTTPS, or strip TLS from the connection.",
                    recommendation="Add the 'Strict-Transport-Security' header to all HTTPS responses. Recommended value: 'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload'. Consider submitting to the HSTS preload list.",
                    references=["CWE-319", "OWASP-A02:2021", "RFC-6797"]
                ))

        return f
