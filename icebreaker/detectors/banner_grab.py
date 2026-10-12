from __future__ import annotations

import asyncio
import re
import httpx
from typing import Iterable, List, Optional, Sequence, Tuple

from rich.console import Console

from icebreaker.core.models import RunContext, Target, Service

console = Console()

# Matches "Product/1.2.3" or "Product 1.2.3" in a Server header
_VERSION_RE = re.compile(r'[\w\-]+[/ ](\d[\d.]+)', re.IGNORECASE)

# Common HTTP ports to probe in addition to 80/443.
# These cover the most frequently encountered non-standard web services.
_DEFAULT_HTTP_PORTS: List[int] = [80, 8080, 8000, 8008, 8888, 3000]
_DEFAULT_HTTPS_PORTS: List[int] = [443, 8443, 8834, 9443]


def _parse_server_version(server: str) -> str:
    """Extract the first version number from a Server header string."""
    m = _VERSION_RE.search(server)
    return m.group(1) if m else ""


def _extract_title(text: str) -> str:
    # dirt simple, fast, good enough for admin panels
    try:
        lower = text.lower()
        lo = lower.find("<title>")
        if lo == -1:
            return ""
        hi = lower.find("</title>", lo)
        if hi == -1:
            return ""
        return text[lo + 7 : hi].strip()
    except Exception:
        return ""


class BannerGrab:
    """
    Lightweight banner/enrichment for HTTP/S.
    One AsyncClient per run; no crawling, just GET / and record headers.

    By default probes a set of common HTTP and HTTPS ports so that services
    on non-standard ports (8080, 8000, 8443, …) are discovered alongside the
    standard 80/443 pair.  Pass ``http_ports`` / ``https_ports`` to override.
    """

    id = "banner_grab"

    def __init__(
        self,
        timeout: float = 1.5,
        quiet: bool = False,
        insecure: bool = False,
        http_ports: Optional[Sequence[int]] = None,
        https_ports: Optional[Sequence[int]] = None,
    ):
        self.timeout = timeout
        self.quiet = quiet
        self.insecure = insecure
        self.http_ports = list(http_ports) if http_ports is not None else _DEFAULT_HTTP_PORTS
        self.https_ports = list(https_ports) if https_ports is not None else _DEFAULT_HTTPS_PORTS

    async def _grab_http(self, client: httpx.AsyncClient, host: str, port: int = 80) -> Tuple[bool, dict]:
        try:
            url = f"http://{host}" if port == 80 else f"http://{host}:{port}"
            r = await client.get(url, follow_redirects=False)
            server = r.headers.get("server", "")
            meta = {
                "server": server,
                "banner": server,                         # normalised key for analyzers
                "version": _parse_server_version(server), # e.g. "2.4.50" from "Apache/2.4.50"
                "title": _extract_title(r.text or ""),
                "status": r.status_code,
                "location": r.headers.get("location", ""),
                "content-security-policy": r.headers.get("content-security-policy", ""),
                "x-frame-options": r.headers.get("x-frame-options", ""),
                "x-content-type-options": r.headers.get("x-content-type-options", ""),
                "x-xss-protection": r.headers.get("x-xss-protection", ""),
                "referrer-policy": r.headers.get("referrer-policy", ""),
                "permissions-policy": r.headers.get("permissions-policy", ""),
                "feature-policy": r.headers.get("feature-policy", ""),
            }
            return True, meta
        except Exception:
            return False, {}

    async def _grab_https(self, client: httpx.AsyncClient, host: str, port: int = 443) -> Tuple[bool, dict]:
        try:
            url = f"https://{host}" if port == 443 else f"https://{host}:{port}"
            r = await client.get(url, follow_redirects=False)
            server = r.headers.get("server", "")
            meta = {
                "server": server,
                "banner": server,
                "version": _parse_server_version(server),
                "title": _extract_title(r.text or ""),
                "status": r.status_code,
                "hsts": r.headers.get("strict-transport-security", ""),
                "content-security-policy": r.headers.get("content-security-policy", ""),
                "x-frame-options": r.headers.get("x-frame-options", ""),
                "x-content-type-options": r.headers.get("x-content-type-options", ""),
                "x-xss-protection": r.headers.get("x-xss-protection", ""),
                "referrer-policy": r.headers.get("referrer-policy", ""),
                "permissions-policy": r.headers.get("permissions-policy", ""),
                "feature-policy": r.headers.get("feature-policy", ""),
            }
            return True, meta
        except Exception:
            return False, {}

    async def run(self, ctx: RunContext, targets: List[Target]) -> Iterable[Service]:
        svcs: list[Service] = []
        quiet = (ctx.settings or {}).get("quiet", self.quiet)

        # Warn if SSL verification is disabled
        if self.insecure and not quiet:
            console.print("[yellow][WARN][/yellow] SSL verification disabled (--insecure flag)")

        async def _probe_target(client: httpx.AsyncClient, t: Target) -> List[Service]:
            results: List[Service] = []
            tasks_http  = [self._grab_http(client, t.address, p)  for p in self.http_ports]
            tasks_https = [self._grab_https(client, t.address, p) for p in self.https_ports]
            gathered = await asyncio.gather(*tasks_http, *tasks_https, return_exceptions=True)

            for i, port in enumerate(self.http_ports):
                ok, meta = gathered[i] if not isinstance(gathered[i], Exception) else (False, {})
                if ok:
                    if not quiet:
                        console.print(f"[blue][BANNER][/blue] {t.address}:{port} -> {meta.get('server','')} \"{meta.get('title','')}\"")
                    results.append(Service(target=t.address, port=port, name="http", meta=meta))

            offset = len(self.http_ports)
            for i, port in enumerate(self.https_ports):
                ok, meta = gathered[offset + i] if not isinstance(gathered[offset + i], Exception) else (False, {})
                if ok:
                    if not quiet:
                        console.print(f"[blue][BANNER][/blue] {t.address}:{port} (https) -> {meta.get('server','')} \"{meta.get('title','')}\"")
                    results.append(Service(target=t.address, port=port, name="https", meta=meta))
            return results

        # One client for the whole pass; probe all targets concurrently
        async with httpx.AsyncClient(timeout=self.timeout, verify=not self.insecure) as client:
            probe_results = await asyncio.gather(*[_probe_target(client, t) for t in targets])
            for target_svcs in probe_results:
                svcs.extend(target_svcs)

        return svcs
