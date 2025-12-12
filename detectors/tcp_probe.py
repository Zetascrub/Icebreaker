from __future__ import annotations

import asyncio
from typing import Iterable, List, Optional, Sequence

from rich.console import Console

from icebreaker.core.models import RunContext, Service, Target
from icebreaker.core.rate_limiter import RateLimiter

console = Console()


_PORT_NAMES = {
    22: "ssh",
    80: "http",
    443: "https",
    # add more well-knowns here if you like
}


class TCPProbe:
    """
    Lightweight TCP connect scanner for a small set of well-known ports.
    This is deliberately simple for v0.1: no SYN scans, no banner work.
    """

    id = "tcp_probe"

    def __init__(
        self,
        ports: Sequence[int] | None = None,
        timeout: float = 1.5,
        quiet: bool = False,
        rate_limit: Optional[float] = None,
    ):
        self.ports = list(ports or [22, 80, 443])
        self.timeout = timeout
        self.quiet = quiet
        self.rate_limit = rate_limit

    async def _try_connect(self, host: str, port: int) -> bool:
        try:
            # asyncio.open_connection resolves and connects; time-bound it
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host=host, port=port), timeout=self.timeout
            )
            # Properly close the connection to avoid resource leaks
            writer.close()
            await writer.wait_closed()
            return True
        except Exception:
            return False

    async def run(self, ctx: RunContext, targets: List[Target]) -> Iterable[Service]:
        services: list[Service] = []
        # Use rate limiter for both concurrency and rate control
        limiter = RateLimiter(max_concurrent=256, rate_per_second=self.rate_limit)

        async def probe_one(host: str, port: int):
            async with limiter:
                ok = await self._try_connect(host, port)
                if ok:
                    name = _PORT_NAMES.get(port, f"tcp/{port}")
                    if not (ctx.settings or {}).get("quiet", self.quiet):
                        console.print(f"[OPEN ] {host}:{port}/tcp {name}")
                    services.append(Service(target=host, port=port, name=name, meta={}))

        tasks: list[asyncio.Task] = []
        for t in targets:
            for p in self.ports:
                tasks.append(asyncio.create_task(probe_one(t.address, p)))

        if tasks:
            await asyncio.gather(*tasks, return_exceptions=False)

        return services
