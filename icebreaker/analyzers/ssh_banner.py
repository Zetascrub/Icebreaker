from __future__ import annotations
import asyncio
from typing import List
from icebreaker.core.models import RunContext, Service, Finding

class SSHBanner:
    id = "ssh_banner"
    consumes = ["service:ssh"]

    async def run(self, ctx: RunContext, service: Service) -> List[Finding]:
        out: list[Finding] = []
        banner = ""
        try:
            # Use async socket operations instead of blocking
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(service.target, service.port),
                timeout=1.0
            )
            # Read SSH banner (SSH servers send banner immediately)
            banner_bytes = await asyncio.wait_for(reader.read(256), timeout=1.0)
            banner = banner_bytes.decode(errors="ignore").strip()
            # Clean up connection
            writer.close()
            await writer.wait_closed()
        except Exception:
            # Silently handle connection errors, banner remains empty
            pass

        if banner:
            out.append(Finding(
                id=f"ssh.banner.{service.target}.{service.port}",
                title="SSH banner exposed",
                severity="INFO",
                target=service.target, port=service.port,
                tags=["ssh","banner"], details={"banner": banner},
            ))
            if "OpenSSH_" in banner:
                try:
                    ver = banner.split("OpenSSH_")[1].split()[0]
                    major = int(ver.split(".")[0])
                    if major <= 7:  # crude, but highlights genuinely old versions
                        out.append(Finding(
                            id=f"ssh.outdated_version.{service.target}.{service.port}",
                            title=f"Possibly outdated OpenSSH ({ver})",
                            severity="LOW",
                            target=service.target, port=service.port,
                            tags=["ssh","version"], details={"version": ver},
                        ))
                except Exception:
                    pass
        return out
