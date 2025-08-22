from __future__ import annotations
from typing import List
from icebreaker.core.models import RunContext, Service, Finding

class HTTPBasic:
    id = "http_basic"
    consumes = ["service:http"]

    async def run(self, ctx: RunContext, service: Service) -> List[Finding]:
        findings: list[Finding] = []
        server = service.meta.get("server", "")
        title = service.meta.get("title", "")
        if server:
            findings.append(Finding(
                id=f"http.server_header.{service.target}.{service.port}",
                title="Server header exposed",
                severity="INFO",
                target=service.target,
                port=service.port,
                tags=["http", "header"],
                details={"server": server},
            ))
        if not title:
            findings.append(Finding(
                id=f"http.missing_title.{service.target}.{service.port}",
                title="Missing or empty page title",
                severity="INFO",
                target=service.target,
                port=service.port,
                tags=["http", "content"],
            ))
        return findings
