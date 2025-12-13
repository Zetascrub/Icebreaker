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
        max_concurrent: int = 128,
        progress_callback=None,  # Callback for progress updates: (current, total) -> None
        verbose: bool = False,  # Enable detailed connection logging
    ):
        self.ports = list(ports or [22, 80, 443])
        self.timeout = timeout
        self.quiet = quiet
        self.rate_limit = rate_limit
        self.max_concurrent = max_concurrent
        self.progress_callback = progress_callback
        self.verbose = verbose
        self.completed_probes = 0
        self.total_probes = 0
        self.connection_errors = {}  # Track errors for diagnostics

    async def _try_connect(self, host: str, port: int, verbose: bool = False) -> tuple[bool, Optional[str]]:
        """
        Try to connect to a host:port.

        Returns:
            (success, error_message) tuple
        """
        import logging
        logger = logging.getLogger(__name__)

        try:
            # asyncio.open_connection resolves and connects; time-bound it
            if verbose:
                logger.info(f"TCPProbe: Attempting connection to {host}:{port} (timeout={self.timeout}s)")

            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host=host, port=port), timeout=self.timeout
            )
            # Properly close the connection to avoid resource leaks
            writer.close()
            await writer.wait_closed()

            if verbose:
                logger.info(f"TCPProbe: ✓ Successfully connected to {host}:{port}")
            return True, None

        except asyncio.TimeoutError as e:
            error_msg = f"Timeout after {self.timeout}s"
            if verbose:
                logger.warning(f"TCPProbe: ✗ {host}:{port} - {error_msg}")
            return False, error_msg

        except ConnectionRefusedError as e:
            error_msg = "Connection refused"
            if verbose:
                logger.warning(f"TCPProbe: ✗ {host}:{port} - {error_msg}")
            return False, error_msg

        except OSError as e:
            error_msg = f"OS Error: {e}"
            if verbose:
                logger.warning(f"TCPProbe: ✗ {host}:{port} - {error_msg}")
            return False, error_msg

        except Exception as e:
            error_msg = f"{type(e).__name__}: {e}"
            if verbose:
                logger.error(f"TCPProbe: ✗ {host}:{port} - Unexpected error: {error_msg}")
            return False, error_msg

    async def run(self, ctx: RunContext, targets: List[Target]) -> Iterable[Service]:
        services: list[Service] = []
        # Use rate limiter for both concurrency and rate control
        limiter = RateLimiter(max_concurrent=self.max_concurrent, rate_per_second=self.rate_limit)

        # Calculate total probes
        self.total_probes = len(targets) * len(self.ports)
        self.completed_probes = 0

        async def probe_one(host: str, port: int):
            async with limiter:
                ok, error_msg = await self._try_connect(host, port, verbose=self.verbose)
                if ok:
                    name = _PORT_NAMES.get(port, f"tcp/{port}")
                    if not (ctx.settings or {}).get("quiet", self.quiet):
                        console.print(f"[OPEN ] {host}:{port}/tcp {name}")
                    services.append(Service(target=host, port=port, name=name, meta={}))
                elif error_msg and self.verbose:
                    # Track error types for diagnostics
                    error_type = error_msg.split(':')[0]
                    if error_type not in self.connection_errors:
                        self.connection_errors[error_type] = []
                    self.connection_errors[error_type].append(f"{host}:{port}")

                # Update progress
                self.completed_probes += 1
                if self.progress_callback and self.completed_probes % 10 == 0:  # Update every 10 probes
                    try:
                        if asyncio.iscoroutinefunction(self.progress_callback):
                            await self.progress_callback(self.completed_probes, self.total_probes)
                        else:
                            self.progress_callback(self.completed_probes, self.total_probes)
                    except Exception:
                        pass  # Don't let progress callback failures break the scan

        tasks: list[asyncio.Task] = []
        for t in targets:
            for p in self.ports:
                tasks.append(asyncio.create_task(probe_one(t.address, p)))

        if tasks:
            await asyncio.gather(*tasks, return_exceptions=False)

        # Final progress update
        if self.progress_callback:
            try:
                if asyncio.iscoroutinefunction(self.progress_callback):
                    await self.progress_callback(self.total_probes, self.total_probes)
                else:
                    self.progress_callback(self.total_probes, self.total_probes)
            except Exception:
                pass

        # Log error summary if verbose
        if self.verbose and self.connection_errors:
            import logging
            logger = logging.getLogger(__name__)
            logger.info(f"TCPProbe: Scan complete. Found {len(services)} open ports out of {self.total_probes} probes")
            logger.info(f"TCPProbe: Connection errors summary:")
            for error_type, ports in self.connection_errors.items():
                logger.info(f"  - {error_type}: {len(ports)} ports (sample: {ports[:5]})")

        return services
