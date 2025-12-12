"""
ICMP Ping Sweep - Discover alive hosts before port scanning.
"""
import asyncio
import logging
import platform
import subprocess
from typing import List, Dict, Tuple
from concurrent.futures import ThreadPoolExecutor

logger = logging.getLogger(__name__)


class PingSweep:
    """Performs ICMP ping sweep to identify alive hosts."""

    def __init__(self, timeout: float = 1.0, max_concurrent: int = 50):
        """
        Initialize ping sweep.

        Args:
            timeout: Timeout for each ping in seconds
            max_concurrent: Maximum concurrent ping operations
        """
        self.timeout = timeout
        self.max_concurrent = max_concurrent
        self.is_windows = platform.system().lower() == "windows"

    async def sweep(self, targets: List[str], progress_callback=None) -> Dict[str, bool]:
        """
        Perform ping sweep on targets.

        Args:
            targets: List of IP addresses or hostnames
            progress_callback: Optional callback for progress updates (current, total)

        Returns:
            Dictionary mapping target -> is_alive (True/False)
        """
        logger.info(f"Starting ping sweep for {len(targets)} targets")
        results = {}

        # Use ThreadPoolExecutor for parallel ping operations
        with ThreadPoolExecutor(max_workers=self.max_concurrent) as executor:
            loop = asyncio.get_event_loop()
            tasks = []

            for target in targets:
                task = loop.run_in_executor(executor, self._ping_host, target)
                tasks.append((target, task))

            # Process results as they complete
            completed = 0
            for target, task in tasks:
                try:
                    is_alive = await task
                    results[target] = is_alive
                    completed += 1

                    if is_alive:
                        logger.debug(f"Host {target} is alive")

                    # Call progress callback
                    if progress_callback:
                        await progress_callback(completed, len(targets))

                except Exception as e:
                    logger.error(f"Error pinging {target}: {e}")
                    results[target] = False
                    completed += 1

                    if progress_callback:
                        await progress_callback(completed, len(targets))

        alive_count = sum(1 for v in results.values() if v)
        logger.info(f"Ping sweep complete: {alive_count}/{len(targets)} hosts alive")

        return results

    def _ping_host(self, target: str) -> bool:
        """
        Ping a single host (blocking operation).

        Args:
            target: IP address or hostname

        Returns:
            True if host responds, False otherwise
        """
        try:
            # Build ping command based on OS
            if self.is_windows:
                # Windows: ping -n 1 -w timeout_ms target
                cmd = ["ping", "-n", "1", "-w", str(int(self.timeout * 1000)), target]
            else:
                # Linux/Unix: ping -c 1 -W timeout_sec target
                cmd = ["ping", "-c", "1", "-W", str(int(self.timeout)), target]

            # Run ping command
            result = subprocess.run(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=self.timeout + 1  # Add buffer to subprocess timeout
            )

            # Check if ping was successful (return code 0)
            return result.returncode == 0

        except subprocess.TimeoutExpired:
            logger.debug(f"Ping timeout for {target}")
            return False
        except Exception as e:
            logger.error(f"Error pinging {target}: {e}")
            return False

    async def get_alive_hosts(self, targets: List[str]) -> List[str]:
        """
        Get list of alive hosts from targets.

        Args:
            targets: List of IP addresses or hostnames

        Returns:
            List of alive hosts
        """
        results = await self.sweep(targets)
        return [target for target, is_alive in results.items() if is_alive]


# Convenience function
async def ping_targets(targets: List[str], timeout: float = 1.0, max_concurrent: int = 50) -> Tuple[List[str], List[str]]:
    """
    Ping targets and return alive and dead hosts.

    Args:
        targets: List of IP addresses or hostnames
        timeout: Timeout for each ping in seconds
        max_concurrent: Maximum concurrent ping operations

    Returns:
        Tuple of (alive_hosts, dead_hosts)
    """
    sweeper = PingSweep(timeout=timeout, max_concurrent=max_concurrent)
    results = await sweeper.sweep(targets)

    alive = [t for t, is_alive in results.items() if is_alive]
    dead = [t for t, is_alive in results.items() if not is_alive]

    return alive, dead
