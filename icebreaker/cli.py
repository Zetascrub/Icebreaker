from __future__ import annotations

import asyncio
from pathlib import Path
from typing import List

import typer
from rich.console import Console

from icebreaker.core.models import RunContext, Target, Service, Finding
from icebreaker.core.util import read_targets
from icebreaker.core.port_parser import parse_port_spec, get_top_ports
from icebreaker.engine.orchestrator import Orchestrator

# detectors
from icebreaker.detectors.tcp_probe import TCPProbe
from icebreaker.detectors.banner_grab import BannerGrab

# analyzers
from icebreaker.analyzers.http_basic import HTTPBasic
from icebreaker.analyzers.security_headers import SecurityHeaders
from icebreaker.analyzers.tls_analyzer import TLSAnalyzer
from icebreaker.analyzers.info_disclosure import InfoDisclosure
try:
    from icebreaker.analyzers.ssh_banner import SSHBanner
    _HAS_SSH = True
except Exception:
    _HAS_SSH = False

# writers
from icebreaker.writers.jsonl import JSONLWriter
from icebreaker.writers.markdown import MarkdownWriter
from icebreaker.writers.sarif import SARIFWriter
from icebreaker.writers.html_writer import HTMLWriter
# CSV writer is optional; if you haven't added it yet, this will be ignored cleanly
try:
    from icebreaker.writers.csv_writer import CSVWriter  # type: ignore
    _HAS_CSV = True
except Exception:
    _HAS_CSV = False

# AI summary writer
from icebreaker.writers.ai_summary import AISummaryWriter


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
    insecure: bool = typer.Option(False, "--insecure", "-k", help="Disable SSL certificate verification"),
    ports: str | None = typer.Option(None, "--ports", "-p", help="Ports to scan (e.g., '80,443' or '8000-8100' or 'top100')"),
    ai: str | None = typer.Option(None, "--ai", help="Enable AI analysis (providers: ollama, anthropic/claude, openai)"),
    ai_model: str | None = typer.Option(None, "--ai-model", help="AI model to use (provider-specific, e.g., 'llama3.2', 'claude-3-5-sonnet-20241022', 'gpt-4o')"),
    ai_base_url: str | None = typer.Option(None, "--ai-base-url", help="Base URL for AI provider (e.g., 'http://192.168.1.100:11434' for remote Ollama)"),
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

    # Parse port specification
    port_list = None
    if ports:
        if ports.lower() == 'top100':
            port_list = get_top_ports(100)
        elif ports.lower() == 'top1000':
            port_list = get_top_ports(1000)
        else:
            try:
                port_list = parse_port_spec(ports)
            except ValueError as e:
                console.print(f"[red]Error:[/red] {e}")
                raise typer.Exit(code=1)

    # Wire detectors / analyzers / writers
    detectors = [
        TCPProbe(timeout=timeout, quiet=quiet, ports=port_list),
        BannerGrab(timeout=timeout, quiet=quiet, insecure=insecure),
    ]


    analyzers: List[object] = [
        HTTPBasic(),
        SecurityHeaders(),
        TLSAnalyzer(),
        InfoDisclosure(),
    ]
    if _HAS_SSH:
        analyzers.append(SSHBanner())

    writers = [JSONLWriter(), MarkdownWriter(), SARIFWriter(), HTMLWriter()]
    if _HAS_CSV:
        writers.append(CSVWriter())     # optional

    # Add AI summary writer if requested
    if ai:
        try:
            ai_writer = AISummaryWriter(ai_provider=ai, ai_model=ai_model, base_url=ai_base_url)
            writers.append(ai_writer)
            if not quiet:
                model_info = ai_model or 'default model'
                url_info = f" @ {ai_base_url}" if ai_base_url else ""
                console.print(f"[cyan]AI Analysis enabled:[/cyan] {ai} ({model_info}{url_info})")
        except Exception as e:
            console.print(f"[yellow]Warning:[/yellow] Could not initialize AI writer: {e}")
            console.print("[yellow]Continuing without AI analysis...[/yellow]")

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
