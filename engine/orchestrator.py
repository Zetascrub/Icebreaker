from __future__ import annotations
import json
from pathlib import Path
from typing import Iterable, List
from rich.table import Table
from rich.panel import Panel
from rich.console import Console

from icebreaker.core.models import RunContext, Target, Service, Finding
from icebreaker.core.util import gather_limited

console = Console()


class Orchestrator:
    def __init__(self, ctx: RunContext, detectors, analyzers, writers, *, host_conc: int = 128, svc_conc: int = 256):
        self.ctx = ctx
        self.detectors = detectors
        self.analyzers = analyzers
        self.writers = writers
        self.host_conc = host_conc
        self.svc_conc = svc_conc

        async def discover(self, targets: list[Target]) -> list[Service]:
            console.print(f"[bold cyan][PROBE][/bold cyan] discovering services on {len(targets)} targets")
            services: list[Service] = []
            for det in self.detectors:
                discovered = await det.run(self.ctx, targets)
                services.extend(discovered)

            # De-duplicate by (target, port, name); merge meta if present
            dedup: dict[tuple[str, int, str], Service] = {}
            for svc in services:
                key = (svc.target, svc.port, svc.name or "unknown")
                if key not in dedup:
                    dedup[key] = svc
                else:
                    # prefer existing name, merge metadata non-destructively
                    dedup[key].meta.update({k: v for k, v in svc.meta.items() if v})

            services = list(dedup.values())

            # Write per-target service meta files
            for svc in services:
                svc_dir = Path(self.ctx.out_dir) / "targets" / svc.target / f"services/{svc.port}-{svc.name or 'unknown'}"
                svc_dir.mkdir(parents=True, exist_ok=True)
                (svc_dir / "meta.json").write_text(json.dumps(svc.model_dump(), indent=2))
            return services


    async def analyse(self, services: list[Service]) -> list[Finding]:
        console.print(f"[bold cyan][SCAN][/bold cyan] analysing {len(services)} services")
        findings: list[Finding] = []

        async def run_one(svc: Service) -> list[Finding]:
            svc_findings: list[Finding] = []
            for analyzer in self.analyzers:
                # crude routing: match on service name
                if any(token == f"service:{svc.name}" for token in analyzer.consumes):
                    out = await analyzer.run(self.ctx, svc)
                    svc_findings.extend(out)
            return svc_findings

        batches = [run_one(s) for s in services]
        results = await gather_limited(self.svc_conc, batches)
        for flist in results:
            findings.extend(flist)
        return findings

    def write_outputs(self, services: list[Service], findings: list[Finding]):
        for writer in self.writers:
            writer.write(self.ctx, services, findings)

        # quick terminal summary
        table = Table(title="Icebreaker Summary")
        table.add_column("Target")
        table.add_column("Port")
        table.add_column("Service")
        table.add_column("Findings")
        svc_index = {}
        for s in services:
            key = (s.target, s.port, s.name or "unknown")
            svc_index[key] = 0
        for f in findings:
            key = (f.target, f.port or 0, next((s.name for s in services if s.target==f.target and s.port==f.port), ""))
            if key in svc_index:
                svc_index[key] += 1
        for (t, p, n), cnt in sorted(svc_index.items()):
            table.add_row(t, str(p), n or "", str(cnt))
        console.print(Panel(table))
