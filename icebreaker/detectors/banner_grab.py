from __future__ import annotations

import httpx
import ssl
from typing import Iterable, List, Tuple
from datetime import datetime

from rich.console import Console

from icebreaker.core.models import RunContext, Target, Service

console = Console()


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
    """

    id = "banner_grab"

    def __init__(self, timeout: float = 1.5, quiet: bool = False, insecure: bool = False):
        self.timeout = timeout
        self.quiet = quiet
        self.insecure = insecure

    async def _grab_http(self, client: httpx.AsyncClient, host: str) -> Tuple[bool, dict]:
        try:
            r = await client.get(f"http://{host}", follow_redirects=False)
            meta = {
                "server": r.headers.get("server", ""),
                "title": _extract_title(r.text or ""),
                "status": r.status_code,
                "location": r.headers.get("location", ""),
                # Security headers
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

    async def _grab_https(self, client: httpx.AsyncClient, host: str) -> Tuple[bool, dict]:
        try:
            r = await client.get(f"https://{host}", follow_redirects=False)

            # Extract TLS/SSL certificate information
            tls_info = {}
            try:
                # Get the SSL certificate from the connection
                # Create a new connection to get cert details
                import socket
                context = ssl.create_default_context()
                if self.insecure:
                    context.check_hostname = False
                    context.verify_mode = ssl.CERT_NONE

                with socket.create_connection((host, 443), timeout=2) as sock:
                    with context.wrap_socket(sock, server_hostname=host) as ssock:
                        cert = ssock.getpeercert()
                        tls_version = ssock.version()

                        if cert:
                            # Extract certificate details
                            subject = dict(x[0] for x in cert.get('subject', []))
                            issuer = dict(x[0] for x in cert.get('issuer', []))

                            # Get Subject Alternative Names
                            san_list = []
                            for san in cert.get('subjectAltName', []):
                                san_list.append(f"{san[0]}:{san[1]}")

                            tls_info = {
                                "tls_version": tls_version,
                                "cert_subject": subject.get('commonName', ''),
                                "cert_issuer": issuer.get('commonName', ''),
                                "cert_issuer_org": issuer.get('organizationName', ''),
                                "cert_valid_from": cert.get('notBefore', ''),
                                "cert_valid_until": cert.get('notAfter', ''),
                                "cert_san": san_list,
                                "cert_serial": cert.get('serialNumber', '')
                            }
            except Exception as e:
                # If cert extraction fails, continue without it
                pass

            meta = {
                "server": r.headers.get("server", ""),
                "title": _extract_title(r.text or ""),
                "status": r.status_code,
                "hsts": r.headers.get("strict-transport-security", ""),
                # Security headers
                "content-security-policy": r.headers.get("content-security-policy", ""),
                "x-frame-options": r.headers.get("x-frame-options", ""),
                "x-content-type-options": r.headers.get("x-content-type-options", ""),
                "x-xss-protection": r.headers.get("x-xss-protection", ""),
                "referrer-policy": r.headers.get("referrer-policy", ""),
                "permissions-policy": r.headers.get("permissions-policy", ""),
                "feature-policy": r.headers.get("feature-policy", ""),
                # TLS/SSL information
                **tls_info
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

        # One client for the whole pass
        async with httpx.AsyncClient(timeout=self.timeout, verify=not self.insecure) as client:
            for t in targets:
                ok80, meta80 = await self._grab_http(client, t.address)
                if ok80:
                    if not quiet:
                        console.print(f"[blue][BANNER][/blue] {t.address}:80 -> {meta80.get('server','')} \"{meta80.get('title','')}\"")
                    svcs.append(Service(target=t.address, port=80, name="http", meta=meta80))

                ok443, meta443 = await self._grab_https(client, t.address)
                if ok443:
                    if not quiet:
                        console.print(f"[blue][BANNER][/blue] {t.address}:443 -> {meta443.get('server','')} \"{meta443.get('title','')}\"")
                    svcs.append(Service(target=t.address, port=443, name="https", meta=meta443))

        return svcs
