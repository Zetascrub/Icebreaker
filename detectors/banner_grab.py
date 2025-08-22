from __future__ import annotations

import httpx
from typing import Iterable, List, Tuple

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

    def __init__(self, timeout: float = 1.5, quiet: bool = False):
        self.timeout = timeout
        self.quiet = quiet

    async def _grab_http(self, client: httpx.AsyncClient, host: str) -> Tuple[bool, dict]:
        try:
            r = await client.get(f"http://{host}", follow_redirects=False)
            meta = {
                "server": r.headers.get("server", ""),
                "title": _extract_title(r.text or ""),
                "status": r.status_code,
                "location": r.headers.get("location", ""),
            }
            return True, meta
        except Exception:
            return False, {}

    async def _grab_https(self, client: httpx.AsyncClient, host: str) -> Tuple[bool, dict]:
        try:
            r = await client.get(f"https://{host}", follow_redirects=False)
            meta = {
                "server": r.headers.get("server", ""),
                "title": _extract_title(r.text or ""),
                "status": r.status_code,
                "hsts": r.headers.get("strict-transport-security", ""),
            }
            return True, meta
        except Exception:
            return False, {}

    async def run(self, ctx: RunContext, targets: List[Target]) -> Iterable[Service]:
        svcs: list[Service] = []
        quiet = (ctx.settings or {}).get("quiet", self.quiet)

        # One client for the whole pass; disable cert verify to avoid local appliances moaning
        async with httpx.AsyncClient(timeout=self.timeout, verify=False) as client:
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
