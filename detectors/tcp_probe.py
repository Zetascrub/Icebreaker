from __future__ import annotations
import asyncio
import socket
from typing import Iterable, List
from icebreaker.core.models import RunContext, Target, Service
from icebreaker.core.util import console, gather_limited

DEFAULT_PORTS = [22, 80, 443]


class TCPProbe:
    id = "tcp_probe"

    def __init__(self, ports: list[int] | None = None, timeout: float = 0.8):
        self.ports = ports or DEFAULT_PORTS
        self.timeout = timeout

    async def _probe(self, host: str, port: int) -> Service | None:
        conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        conn.setblocking(False)
        try:
            await asyncio.wait_for(asyncio.get_event_loop().sock_connect(conn, (host, port)), timeout=self.timeout)
            # bare minimum name guess
            name = {80: "http", 443: "https", 22: "ssh"}.get(port, None)
            console.print(f"[green][OPEN ][/green] {host}:{port}/tcp {name or ''}")
            return Service(target=host, port=port, name=name)
        except Exception:
            return None
        finally:
            conn.close()

    async def run(self, ctx: RunContext, targets: list[Target]) -> Iterable[Service]:
        coros = []
        for t in targets:
            for p in self.ports:
                coros.append(self._probe(t.address, p))
        results = await gather_limited(256, coros)
        return [r for r in results if r]
