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
                tags=["http", "header"], details={"server": server},
            ))
        if service.name == "http" and not title:
            f.append(Finding(
                id=f"http.missing_title.{service.target}.{service.port}",
                title="Missing or empty page title",
                severity="INFO",
                target=service.target, port=service.port,
                tags=["http", "content"],
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
                ))

        return f
