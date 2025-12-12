"""
Nmap-based port scanner for faster scanning of large networks.

This detector uses nmap for significantly faster scanning compared to pure Python TCP connect.
Requires nmap to be installed on the system.
"""
from __future__ import annotations

import asyncio
import logging
from typing import Iterable, List, Optional, Sequence

from rich.console import Console

from icebreaker.core.models import RunContext, Service, Target

console = Console()
logger = logging.getLogger(__name__)


class NmapProbe:
    """
    Nmap-based port scanner.

    Uses nmap for faster scanning of large networks. Falls back to TCP probe if nmap is not available.
    """

    id = "nmap_probe"

    def __init__(
        self,
        ports: Sequence[int] | None = None,
        timeout: float = 1.5,
        quiet: bool = False,
        scan_arguments: str = "-sS -T4",  # SYN scan, aggressive timing
        progress_callback=None,
    ):
        """
        Initialize nmap scanner.

        Args:
            ports: List of ports to scan
            timeout: Timeout for each host (passed to nmap)
            quiet: Suppress output
            scan_arguments: Nmap scan arguments (default: -sS -T4 for SYN scan)
            progress_callback: Optional callback for progress updates
        """
        self.ports = list(ports or [22, 80, 443])
        self.timeout = timeout
        self.quiet = quiet
        self.scan_arguments = scan_arguments
        self.progress_callback = progress_callback

        # Check if nmap is available
        self._nmap_available = self._check_nmap()

    def _check_nmap(self) -> bool:
        """Check if nmap is installed and accessible."""
        try:
            import subprocess
            result = subprocess.run(
                ["nmap", "--version"],
                capture_output=True,
                timeout=5
            )
            return result.returncode == 0
        except Exception as e:
            logger.warning(f"Nmap not available: {e}")
            return False

    async def run(self, ctx: RunContext, targets: List[Target]) -> Iterable[Service]:
        """
        Run nmap scan on targets.

        Args:
            ctx: Run context
            targets: List of targets to scan

        Returns:
            List of discovered services
        """
        if not self._nmap_available:
            logger.warning("Nmap not available, cannot scan")
            return []

        services: list[Service] = []

        # Convert port list to nmap format
        port_spec = ",".join(map(str, self.ports))

        # Build target list
        target_addresses = [t.address for t in targets]

        # Calculate total for progress tracking
        total_targets = len(target_addresses)
        completed_targets = 0

        logger.info(f"Scanning {total_targets} targets with nmap...")

        # Scan targets in batches to provide progress updates
        batch_size = 10  # Scan 10 hosts at a time for progress updates
        for i in range(0, len(target_addresses), batch_size):
            batch = target_addresses[i:i + batch_size]

            # Run nmap on this batch
            batch_services = await self._scan_batch(batch, port_spec, ctx)
            services.extend(batch_services)

            # Update progress
            completed_targets += len(batch)
            if self.progress_callback:
                # Calculate total probes (for compatibility with TCPProbe callback)
                current_probes = completed_targets * len(self.ports)
                total_probes = total_targets * len(self.ports)

                try:
                    if asyncio.iscoroutinefunction(self.progress_callback):
                        await self.progress_callback(current_probes, total_probes)
                    else:
                        self.progress_callback(current_probes, total_probes)
                except Exception:
                    pass

        return services

    async def _scan_batch(self, targets: List[str], port_spec: str, ctx: RunContext) -> List[Service]:
        """
        Scan a batch of targets with nmap.

        Args:
            targets: List of target addresses
            port_spec: Port specification (e.g., "22,80,443")
            ctx: Run context

        Returns:
            List of services found
        """
        import subprocess
        import xml.etree.ElementTree as ET

        services = []

        # Build nmap command
        target_list = " ".join(targets)
        cmd = [
            "nmap",
            "-p", port_spec,
            "--host-timeout", f"{int(self.timeout)}s",
            "-oX", "-",  # Output XML to stdout
        ]

        # Add scan arguments
        if self.scan_arguments:
            cmd.extend(self.scan_arguments.split())

        # Add targets
        cmd.extend(targets)

        if not ctx.settings.get("quiet", self.quiet):
            logger.info(f"Running: {' '.join(cmd)}")

        # Run nmap asynchronously
        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )

            stdout, stderr = await process.communicate()

            if process.returncode != 0:
                logger.error(f"Nmap failed: {stderr.decode()}")
                return services

            # Parse XML output
            try:
                root = ET.fromstring(stdout.decode())

                for host in root.findall("host"):
                    # Get host address
                    address_elem = host.find("address")
                    if address_elem is None:
                        continue

                    host_addr = address_elem.get("addr")

                    # Get open ports
                    ports_elem = host.find("ports")
                    if ports_elem is None:
                        continue

                    for port_elem in ports_elem.findall("port"):
                        state_elem = port_elem.find("state")
                        if state_elem is None or state_elem.get("state") != "open":
                            continue

                        port_num = int(port_elem.get("portid"))

                        # Get service info
                        service_elem = port_elem.find("service")
                        service_name = "unknown"
                        if service_elem is not None:
                            service_name = service_elem.get("name", "unknown")

                        # Create service
                        svc = Service(
                            target=host_addr,
                            port=port_num,
                            name=service_name,
                            meta={}
                        )
                        services.append(svc)

                        if not ctx.settings.get("quiet", self.quiet):
                            console.print(f"[OPEN ] {host_addr}:{port_num}/tcp {service_name}")

            except ET.ParseError as e:
                logger.error(f"Failed to parse nmap XML output: {e}")

        except Exception as e:
            logger.error(f"Nmap execution failed: {e}")

        return services
