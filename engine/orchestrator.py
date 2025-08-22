from __future__ import annotations

import json
from pathlib import Path
from typing import Dict, List, Tuple

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from icebreaker.core.models import Finding, RunContext, Service, Target

console = Console()


class Orchestrator:
    def __init__(
        self,
        ctx: RunContext,
        detectors,
        analyzers,
        writers,
        *,
        host_conc: int = 128,
        svc_conc: int = 256,
        quiet: bool = False,
    ):
        self.ctx = ctx
        self.detectors = detectors
        self.analyzers = analyzers
        self.writers = writers
        self.host_conc = host_conc
        self.svc_conc = svc_conc
        self.quiet = quiet

    async def discover(self, targets: List[Target]) -> List[Service]:
        if not self.quiet:
            console.print(f"[bold cyan][PROBE][/bold cyan] discovering services on {len(targets)} targets")

        services: List[Service] = []
        for det in self.detectors:
            discovered = await det.run(self.ctx, targets)
            services.extend(discovered)

        # De-duplicate by (target, port, name) and merge banner/meta details
        dedup: Dict[Tuple[str, int, str], Service] = {}
        for svc in services:
            key = (svc.target, svc.port, svc.name or "unknown")
            if key not in dedup:
                dedup[key] = svc
            else:
                # Keep existing object; merge any truthy fields from the later entry
                dedup[key].meta.update({k: v for (k, v) in (svc.meta or {}).items() if v})

        services = list(dedup.values())

        # Persist per-service metadata for later tooling
        for svc in services:
            svc_dir = (
                Path(self.ctx.out_dir)
                / "targets"
                / svc.target
                / f"services/{svc.port}-{(svc.name or 'unknown')}"
            )
            svc_dir.mkdir(parents=True, exist_ok=True)
            (svc_dir / "meta.json").write_text(json.dumps(svc.model_dump(), indent=2), encoding="utf-8")

        return services

    async def analyse(self, services: List[Service]) -> List[Finding]:
        if not self.quiet:
            console.print(f"[bold magenta][SCAN][/bold magenta] analysing {len(services)} services")

        findings: List[Finding] = []
        for analyzer in self.analyzers:
            for svc in services:
                try:
                    consumes = getattr(analyzer, "consumes", None)
                    if consumes and svc.name and f"service:{svc.name}" not in consumes:
                        continue
                    results = await analyzer.run(self.ctx, svc)
                    findings.extend(results)
                except Exception as e:  # keep the engine resilient in 0.1
                    if not self.quiet:
                        console.print(f"[red][ERROR][/red] {analyzer.id} on {svc.target}:{svc.port} -> {e}")
        return findings

    def write_outputs(self, services: List[Service], findings: List[Finding]) -> None:
        # Delegate to configured writers
        for writer in self.writers:
            try:
                writer.write(self.ctx, services, findings)
            except Exception as e:
                if not self.quiet:
                    console.print(f"[red][ERROR][/red] writer {getattr(writer, 'id', writer)} failed -> {e}")

        # Terminal summary (quiet hides this)
        if self.quiet:
            return

        table = Table(title="Icebreaker Summary")
        table.add_column("Target")
        table.add_column("Port")
        table.add_column("Service")
        table.add_column("Findings")

        # Count findings per (target, port, name)
        per_service: Dict[Tuple[str, int, str], int] = {}
        for s in services:
            per_service[(s.target, s.port, s.name or "unknown")] = 0

        for f in findings:
            # Find matching service name for this target:port
            name = next((s.name or "" for s in services if s.target == f.target and (f.port or 0) == s.port), "")
            key = (f.target, f.port or 0, name)
            if key in per_service:
                per_service[key] += 1

        for (t, p, n), c in sorted(per_service.items()):
            table.add_row(t, str(p), n, str(c))

        console.print(Panel(table))
