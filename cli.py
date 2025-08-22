from __future__ import annotations
import json
import asyncio
import typer
from rich import print
from pathlib import Path
from icebreaker.core.models import RunContext, Target
from icebreaker.core.util import read_targets
from icebreaker.engine.orchestrator import Orchestrator

# v0.1 built-ins
from icebreaker.detectors.tcp_probe import TCPProbe
from icebreaker.detectors.banner_grab import BannerGrab
from icebreaker.analyzers.http_basic import HTTPBasic
from icebreaker.writers.jsonl import JSONLWriter
from icebreaker.writers.markdown import MarkdownWriter

app = typer.Typer(help="Icebreaker — first-strike recon scanner")


@app.command()
def scan(
    targets: str = typer.Option(..., "--targets", "-t", help="Path to scope file (one host per line)"),
    preset: str = typer.Option("quick", "--preset", help="Preset name (v0.1: quick only)"),
    out_dir: str = typer.Option(None, "--out-dir", help="Output directory (default runs/<id>-<preset>)"),
    host_conc: int = typer.Option(128, help="Concurrent hosts"),
    svc_conc: int = typer.Option(256, help="Concurrent service checks"),
):
    ctx = RunContext.new(preset=preset, out_dir=out_dir)
    Path(ctx.out_dir, "run.json").write_text(ctx.model_dump_json(indent=2))

    addrs = read_targets(targets)
    tgts = [Target(address=a) for a in addrs]

    detectors = [
        TCPProbe(ports=[22,80,443]),
        BannerGrab(),
    ]
    analyzers = [HTTPBasic()]
    writers = [JSONLWriter(), MarkdownWriter()]

    orch = Orchestrator(ctx, detectors, analyzers, writers, host_conc=host_conc, svc_conc=svc_conc)

    async def _run():
        services = await orch.discover(tgts)
        findings = await orch.analyse(services)
        orch.write_outputs(services, findings)
        print(f"[bold green]Done[/bold green]. Output: {ctx.out_dir}")

    asyncio.run(_run())


if __name__ == "__main__":
    app()
