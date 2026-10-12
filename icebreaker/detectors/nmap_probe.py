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

# ---------------------------------------------------------------------------
# CPE synthesis — nmap -sV reports product/version but often omits <cpe> XML
# elements for common software.  This table maps nmap product strings to their
# CPE vendor:product components so we can construct a usable CPE URI.
# ---------------------------------------------------------------------------
_PRODUCT_TO_CPE: dict[str, tuple[str, str]] = {
    # Web servers
    "apache httpd":          ("apache",       "http_server"),
    "apache http server":    ("apache",       "http_server"),
    "nginx":                 ("nginx",        "nginx"),
    "microsoft iis httpd":   ("microsoft",    "internet_information_server"),
    "lighttpd":              ("lighttpd",     "lighttpd"),
    "cherokee httpd":        ("cherokee-project", "cherokee"),
    # App servers
    "apache tomcat":         ("apache",       "tomcat"),
    "jetty":                 ("eclipse",      "jetty"),
    # SSH
    "openssh":               ("openbsd",      "openssh"),
    # FTP
    "vsftpd":                ("vsftpd_project", "vsftpd"),
    "proftpd":               ("proftpd",      "proftpd"),
    "pure-ftpd":             ("pureftpd",     "pure-ftpd"),
    "filezilla server":      ("filezilla-project", "filezilla_server"),
    # Mail
    "postfix smtpd":         ("postfix",      "postfix"),
    "postfix":               ("postfix",      "postfix"),
    "exim smtpd":            ("exim",         "exim"),
    "sendmail":              ("sendmail",     "sendmail"),
    "dovecot imapd":         ("dovecot",      "dovecot"),
    "dovecot pop3d":         ("dovecot",      "dovecot"),
    # Databases
    "mysql":                 ("oracle",       "mysql"),
    "mariadb":               ("mariadb",      "mariadb"),
    "postgresql":            ("postgresql",   "postgresql"),
    "microsoft sql server":  ("microsoft",    "sql_server"),
    "mongodb":               ("mongodb",      "mongodb"),
    "redis":                 ("redis",        "redis"),
    # Printing
    "cups":                  ("openprinting", "cups"),
    # Other
    "openssl":               ("openssl",      "openssl"),
    "samba smbd":            ("samba",        "samba"),
    "samba":                 ("samba",        "samba"),
    "vnc":                   ("realvnc",      "vnc"),
}

# nmap service names that map to canonical names used by analyzers
_CANONICAL_SERVICE_NAME: dict[str, str] = {
    "http-alt":   "http",
    "http-proxy": "http",
    "www":        "http",
    "https-alt":  "https",
    "ssl/http":   "https",
}


def _synthesise_cpe(product: str, version: str) -> str | None:
    """
    Return a CPE 2.2 URI for *product*/*version* using the lookup table, or
    None if the product is not recognised.
    """
    key = product.lower().strip()
    entry = _PRODUCT_TO_CPE.get(key)
    if entry is None:
        # Try prefix match for product strings like "Apache httpd 2.4.58 (Ubuntu)"
        for k, v in _PRODUCT_TO_CPE.items():
            if key.startswith(k):
                entry = v
                break
    if entry is None:
        return None
    vendor, prod = entry
    ver = version.strip() if version else ""
    if ver:
        return f"cpe:/a:{vendor}:{prod}:{ver}"
    return f"cpe:/a:{vendor}:{prod}"


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
        # Effective per-host timeout for nmap.
        # Use at least 60 s for small port lists, scaling to 300 s for
        # large lists (e.g. top-1000).  This prevents nmap from timing out
        # the host on slow-to-respond services like SMB or Nessus.
        n = len(self.ports) if self.ports else 100
        self._host_timeout = min(300, max(60, n))

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
        import tempfile
        import os

        services = []

        # For large target lists, use a target file to avoid "Argument list too long" error
        if len(targets) > 50:
            # Create temporary target file
            with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as tf:
                tf.write('\n'.join(targets))
                target_file = tf.name

            cmd = [
                "nmap",
                "-p", port_spec,
                "--host-timeout", f"{self._host_timeout}s",
                "-oX", "-",  # Output XML to stdout
                "-iL", target_file,  # Read targets from file
            ]

            # Add scan arguments
            if self.scan_arguments:
                cmd.extend(self.scan_arguments.split())

            use_target_file = True
        else:
            # For small lists, pass targets directly
            cmd = [
                "nmap",
                "-p", port_spec,
                "--host-timeout", f"{self._host_timeout}s",
                "-oX", "-",  # Output XML to stdout
            ]

            # Add scan arguments
            if self.scan_arguments:
                cmd.extend(self.scan_arguments.split())

            # Add targets
            cmd.extend(targets)
            use_target_file = False
            target_file = None

        if not ctx.settings.get("quiet", self.quiet):
            logger.info(f"Running nmap on {len(targets)} targets with ports {port_spec}")

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
            else:
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
                            svc_meta: dict = {}
                            if service_elem is not None:
                                raw_name = service_elem.get("name", "unknown")
                                service_name = _CANONICAL_SERVICE_NAME.get(raw_name, raw_name)
                                product  = service_elem.get("product", "")
                                version  = service_elem.get("version", "")
                                extrainfo = service_elem.get("extrainfo", "")
                                # Build a banner string from nmap's version detection (-sV)
                                banner_parts = [p for p in (product, version, extrainfo) if p]
                                banner = " ".join(banner_parts)
                                if banner:
                                    svc_meta["banner"]  = banner
                                    svc_meta["version"] = version
                                # Collect CPE strings emitted by -sV
                                cpes = [
                                    cpe_elem.get("item", "")
                                    for cpe_elem in service_elem.findall("cpe")
                                    if cpe_elem.get("item")
                                ]
                                # nmap -sV often knows the product/version but omits CPE
                                # entries for common software.  Synthesise a CPE from the
                                # product name so that NASL plugins can match by CPE.
                                if not cpes and product and version:
                                    synthesised = _synthesise_cpe(product, version)
                                    if synthesised:
                                        cpes = [synthesised]
                                if cpes:
                                    svc_meta["cpe"] = cpes

                            # Create service
                            svc = Service(
                                target=host_addr,
                                port=port_num,
                                name=service_name,
                                meta=svc_meta,
                            )
                            services.append(svc)

                            if not ctx.settings.get("quiet", self.quiet):
                                console.print(f"[OPEN ] {host_addr}:{port_num}/tcp {service_name}")

                except ET.ParseError as e:
                    logger.error(f"Failed to parse nmap XML output: {e}")

        except Exception as e:
            logger.error(f"Nmap execution failed: {e}")
        finally:
            # Clean up temporary target file if used
            if use_target_file and target_file:
                try:
                    os.unlink(target_file)
                except Exception:
                    pass

        return services
