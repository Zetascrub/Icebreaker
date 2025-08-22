from __future__ import annotations
import httpx
from typing import Iterable, List
from icebreaker.core.models import RunContext, Target, Service
from icebreaker.core.util import console

class BannerGrab:
    id = "banner_grab"

    def __init__(self, timeout: float = 1.5):
        self.timeout = timeout

    async def run(self, ctx: RunContext, targets: list[Target]) -> Iterable[Service]:
        enriched: list[Service] = []
        async with httpx.AsyncClient(timeout=self.timeout, verify=False, follow_redirects=True) as client:
            for t in targets:
                for port, scheme in [(80, "http"), (443, "https")]:
                    url = f"{scheme}://{t.address}"
                    try:
                        r = await client.get(url)
                        text_lower = r.text.lower()
                        lo = text_lower.find("<title>")
                        hi = text_lower.find("</title>", lo) if lo != -1 else -1
                        title = r.text[lo + 7:hi].strip() if lo != -1 and hi != -1 else ""
                        meta = {"server": r.headers.get("server", ""), "title": title}
                        console.print(f"[blue][BANNER][/blue] {t.address}:{port} -> {meta['server']} \"{title}\"")
                        enriched.append(Service(target=t.address, port=port, name=scheme if port == 80 else "https", meta=meta))
                    except Exception:
                        # no banner; skip quietly
                        continue
        return enriched
