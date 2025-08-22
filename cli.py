from __future__ import annotations

import asyncio
from pathlib import Path
from typing import List

import typer
from rich.console import Console

from icebreaker.core.models import RunContext, Target, Service, Finding
from icebreaker.core.util import read_targets
from icebreaker.engine.orchestrator import Orchestrator

# detectors
from icebreaker.detectors.tcp_probe import TCPProbe
from icebreaker.detectors.banner_grab import BannerGrab

# analyzers
from icebreaker.analyzers.http_basic import HTTPBasic
try:
    from icebreaker.analyzers.ssh_banner import SSHBanner
    _HAS_SSH = True
except Exception:
    _HAS_SSH = False

# writers
from icebreaker.writers.jsonl import JSONLWriter
from icebreaker.writers.markdown import MarkdownWriter
# CSV writer is optional; if you haven't added it yet, this will be ignored cleanly
try:
    from icebreaker.writers.csv_writer import CSVWriter  # type: ignore
    _HAS_CSV = True
except Exception:
    _HAS_CSV = False


console = Console()
app = typer.Typer(add_completion=False, no_args_is_help=True, help="Icebreaker — first-strike recon scanner")


@app.callback(invoke_without_command=True)
def main(
    targets: str = typer.Option(..., "--targets", "-t", help="Path to scope file (one host per line)"),
    preset: str = typer.Option("quick", help="Preset name (v0.1: quick only)"),
    out_dir: str | None = typer.Option(None, help="Output directory (default runs/<id>-<preset>)"),
    host_conc: int = typer.Option(128, help="Concurrent hosts"),
    svc_conc: int = typer.Option(256, help="Concurrent service checks"),
    quiet: bool = typer.Option(False, "--quiet", "-q", help="Reduce console output"),
    timeout: float = typer.Option(1.5, help="Per-request timeout (seconds)"),
):
    """
    Single-command entrypoint. Example:
      icebreaker -t scope.txt --preset quick --out-dir /tmp/icebreaker-run
    """
    # Build run context (RunContext.new should set run_id, started_at, default out_dir)
    ctx = RunContext.new(preset=preset, out_dir=out_dir, settings={"quiet": quiet})

    # Write run metadata early (JSON serialised via pydantic)
    Path(ctx.out_dir).mkdir(parents=True, exist_ok=True)
    Path(ctx.out_dir, "run.json").write_text(ctx.model_dump_json(indent=2), encoding="utf-8")

    # Load targets
    addrs = read_targets(targets)
    tgts: List[Target] = [Target(address=a) for a in addrs]

    # Wire detectors / analyzers / writers
    detectors = [
        TCPProbe(timeout=timeout, quiet=quiet),
        BannerGrab(timeout=timeout, quiet=quiet),
    ]


    analyzers: List[object] = [HTTPBasic()]
    if _HAS_SSH:
        analyzers.append(SSHBanner())

    writers = [JSONLWriter(), MarkdownWriter()]
    if _HAS_CSV:
        writers.append(CSVWriter())     # optional

    orch = Orchestrator(
        ctx,
        detectors=detectors,
        analyzers=analyzers,
        writers=writers,
        host_conc=host_conc,
        svc_conc=svc_conc,
        quiet=quiet,
    )

    async def _run():
        services: List[Service] = await orch.discover(tgts)
        findings: List[Finding] = await orch.analyse(services)
        orch.write_outputs(services, findings)
        if not quiet:
            console.print(f"[bold green]Done[/bold green]. Output: {ctx.out_dir}")
        return findings

    try:
        findings = asyncio.run(_run())
        # Exit codes: 0 = clean, 2 = findings present (useful in CI/scripts)
        raise typer.Exit(code=0 if not findings else 2)
    except typer.Exit:
        raise
    except Exception as e:
        console.print(f"[red]Fatal:[/red] {e}")
        raise typer.Exit(code=1)


if __name__ == "__main__":
    app()
