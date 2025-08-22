from __future__ import annotations
import asyncio
from pathlib import Path
from typing import Iterable
from rich.console import Console

console = Console()

def read_targets(path: str) -> list[str]:
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(path)
    lines = [ln.strip() for ln in p.read_text().splitlines() if ln.strip() and not ln.startswith("#")]
    return lines

async def gather_limited(n: int, coros: Iterable):
    sem = asyncio.Semaphore(n)
    async def _wrap(coro):
        async with sem:
            return await coro
    return await asyncio.gather(*[_wrap(c) for c in coros], return_exceptions=False)
