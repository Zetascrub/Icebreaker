from __future__ import annotations
import asyncio
import re
from pathlib import Path
from typing import Iterable
from rich.console import Console

console = Console()

# Patterns for validating IP addresses and hostnames
_IPV4_PATTERN = re.compile(
    r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
)
_IPV6_PATTERN = re.compile(
    r'^(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$|'
    r'^::(?:[0-9a-fA-F]{1,4}:){0,6}[0-9a-fA-F]{1,4}$|'
    r'^[0-9a-fA-F]{1,4}::(?:[0-9a-fA-F]{1,4}:){0,5}[0-9a-fA-F]{1,4}$'
)
_HOSTNAME_PATTERN = re.compile(
    r'^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(?:\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*\.?$'
)

def validate_target(target: str) -> bool:
    """Validate that a target is a valid IP address or hostname."""
    if not target or len(target) > 253:
        return False

    # Check if it's a valid IPv4 address
    if _IPV4_PATTERN.match(target):
        return True

    # Check if it's a valid IPv6 address
    if _IPV6_PATTERN.match(target):
        return True

    # Check if it's a valid hostname
    if _HOSTNAME_PATTERN.match(target):
        return True

    return False

def read_targets(path: str) -> list[str]:
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(path)
    lines = [ln.strip() for ln in p.read_text().splitlines() if ln.strip() and not ln.startswith("#")]

    # Validate all targets
    validated = []
    for line in lines:
        if validate_target(line):
            validated.append(line)
        else:
            console.print(f"[yellow][WARN][/yellow] Skipping invalid target: {line}")

    if not validated:
        raise ValueError("No valid targets found in scope file")

    return validated

async def gather_limited(n: int, coros: Iterable):
    sem = asyncio.Semaphore(n)
    async def _wrap(coro):
        async with sem:
            return await coro
    return await asyncio.gather(*[_wrap(c) for c in coros], return_exceptions=False)
