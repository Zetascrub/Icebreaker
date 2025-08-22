from __future__ import annotations
from typing import List
from icebreaker.core.models import RunContext, Service, Finding
import socket

class SSHBanner:
    id = "ssh_banner"
    consumes = ["service:ssh"]

    async def run(self, ctx: RunContext, service: Service) -> List[Finding]:
        out: list[Finding] = []
        try:
            with socket.create_connection((service.target, service.port), timeout=1.0) as s:
                s.settimeout(1.0)
                banner = s.recv(256).decode(errors="ignore").strip()  # e.g. SSH-2.0-OpenSSH_9.6p1 Debian-3
        except Exception:
            banner = ""

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
