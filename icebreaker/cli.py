from __future__ import annotations

import asyncio
from pathlib import Path
from typing import List
import tarfile
import tempfile
import shutil

import typer
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn

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
from icebreaker.analyzers.dns import DNSAnalyzer
from icebreaker.analyzers.api_discovery import APIDiscovery
from icebreaker.analyzers.waf_cdn import WAFCDNDetector
from icebreaker.analyzers.smb_analyzer import SMBAnalyzer
try:
    from icebreaker.analyzers.ssh_banner import SSHBanner
    _HAS_SSH = True
except Exception:
    _HAS_SSH = False

try:
    from icebreaker.analyzers.nasl_analyzer import NASLAnalyzer
    _HAS_NASL = True
except Exception:
    _HAS_NASL = False

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

# Import command subapp
import_app = typer.Typer(help="Import vulnerability data from external sources")
app.add_typer(import_app, name="import")


@app.callback(invoke_without_command=True)
def main(
    ctx: typer.Context,
    targets: str = typer.Option(None, "--targets", "-t", help="Path to scope file (one host per line)"),
    preset: str = typer.Option("quick", help="Preset name (v0.1: quick only)"),
    out_dir: str | None = typer.Option(None, help="Output directory (default runs/<id>-<preset>)"),
    host_conc: int = typer.Option(128, help="Concurrent hosts"),
    svc_conc: int = typer.Option(256, help="Concurrent service checks"),
    quiet: bool = typer.Option(False, "--quiet", "-q", help="Reduce console output"),
    timeout: float = typer.Option(1.5, help="Per-request timeout (seconds)"),
    insecure: bool = typer.Option(False, "--insecure", "-k", help="Disable SSL certificate verification"),
    ports: str | None = typer.Option(None, "--ports", "-p", help="Ports to scan (e.g., '80,443' or '8000-8100' or 'top100')"),
    use_nmap: bool = typer.Option(False, "--nmap", help="Use Nmap for faster scanning (10-100x speedup, requires nmap installed)"),
    ai: str | None = typer.Option(None, "--ai", help="Enable AI analysis (providers: ollama, anthropic/claude, openai)"),
    ai_model: str | None = typer.Option(None, "--ai-model", help="AI model to use (provider-specific, e.g., 'llama3.2', 'claude-3-5-sonnet-20241022', 'gpt-4o')"),
    ai_base_url: str | None = typer.Option(None, "--ai-base-url", help="Base URL for AI provider (e.g., 'http://192.168.1.100:11434' for remote Ollama)"),
):
    """
    Single-command entrypoint. Example:
      icebreaker -t scope.txt --preset quick --out-dir /tmp/icebreaker-run
    """
    # If a subcommand is being invoked (e.g. 'import nessus'), skip scan logic
    if ctx.invoked_subcommand is not None:
        return

    if not targets:
        console.print(ctx.get_help())
        raise typer.Exit(code=0)
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
    # Use Nmap if requested and available, otherwise fall back to TCPProbe
    if use_nmap:
        try:
            from icebreaker.detectors.nmap_probe import NmapProbe
            import os as _os
            _nmap_base = "-sS" if _os.geteuid() == 0 else "-sT"
            detectors = [
                NmapProbe(
                    timeout=timeout, quiet=quiet, ports=port_list,
                    scan_arguments=f"{_nmap_base} -T4",
                ),
                BannerGrab(timeout=timeout, quiet=quiet, insecure=insecure),
            ]
            if not quiet:
                console.print("[cyan]Using Nmap for port scanning[/cyan]")
        except Exception as e:
            console.print(f"[yellow]Warning:[/yellow] Nmap not available ({e}), falling back to TCP probe")
            detectors = [
                TCPProbe(timeout=timeout, quiet=quiet, ports=port_list),
                BannerGrab(timeout=timeout, quiet=quiet, insecure=insecure),
            ]
    else:
        detectors = [
            TCPProbe(timeout=timeout, quiet=quiet, ports=port_list),
            BannerGrab(timeout=timeout, quiet=quiet, insecure=insecure),
        ]

    # Enable all available analyzers
    analyzers: List[object] = [
        HTTPBasic(),
        SecurityHeaders(),
        TLSAnalyzer(),
        InfoDisclosure(),
        SMBAnalyzer(),          # SMB signing, version, service detection
        DNSAnalyzer(),          # DNS reconnaissance
        APIDiscovery(),         # API endpoint discovery
        WAFCDNDetector(),       # WAF and CDN detection
    ]
    if _HAS_SSH:
        analyzers.append(SSHBanner())

    if _HAS_NASL:
        import os
        _nasl_db = "/data/icebreaker.db" if os.path.exists("/data") else "./icebreaker.db"
        try:
            nasl = NASLAnalyzer(db_path=_nasl_db)
            if nasl.plugin_count() > 0:
                analyzers.append(nasl)
                if not quiet:
                    console.print(
                        f"[cyan]NASL plugins:[/cyan] {nasl.plugin_count():,} loaded "
                        f"({nasl.indexed_count():,} indexed checks)"
                    )
        except Exception:
            pass  # silently skip if DB not ready

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


@import_app.command("nessus")
def import_nessus(
    plugins_dir: str = typer.Argument(
        "/opt/nessus/lib/nessus/plugins",
        help="Path to directory containing .nasl files (default: Nessus install location)",
    ),
    db_path: str = typer.Option(
        None,
        "--db",
        help="Path to database file (auto-detected if omitted)",
    ),
    preview_only: bool = typer.Option(False, "--preview", help="Preview stats without importing"),
    sample_size: int = typer.Option(20, "--sample", help="Number of plugins to sample for preview"),
    all_plugins: bool = typer.Option(False, "--all", help="Import all plugins including local-only checks"),
    workers: int = typer.Option(0, "--workers", help="Parallel worker processes (0 = auto)"),
):
    """
    Import Nessus plugins from the local Nessus installation into Icebreaker.

    By default imports only remote/combined plugins (~22k checks that work
    without agent access). Use --all to also import local OS checks.

    Examples:
      icebreaker import nessus
      icebreaker import nessus --preview
      icebreaker import nessus /opt/nessus/lib/nessus/plugins --all
      icebreaker import nessus --workers 8
    """
    from icebreaker.importers.nessus_importer import NessusImporter
    from icebreaker.db.database import init_db

    # Resolve DB path
    if db_path is None:
        import os
        db_path = "/data/icebreaker.db" if os.path.exists("/data") else "./icebreaker.db"

    # Validate plugins directory
    plugins_path = Path(plugins_dir)
    if not plugins_path.exists():
        console.print(f"[red]Error:[/red] Directory not found: {plugins_dir}")
        console.print("[yellow]Hint:[/yellow] Pass the path to a directory containing .nasl files")
        raise typer.Exit(code=1)
    if not plugins_path.is_dir():
        console.print(f"[red]Error:[/red] Not a directory: {plugins_dir}")
        raise typer.Exit(code=1)

    importer = NessusImporter(db_path=db_path, workers=workers or None)
    remote_only = not all_plugins

    # ---- Preview mode -------------------------------------------------- #
    if preview_only:
        console.print(f"[cyan]Scanning[/cyan] {plugins_dir} for NASL plugins…")
        stats = importer.preview(plugins_dir, sample_size=sample_size, remote_only=remote_only)

        if "error" in stats:
            console.print(f"[red]Error:[/red] {stats['error']}")
            raise typer.Exit(code=1)

        console.print(f"\n[bold]Preview Results[/bold]")
        console.print(f"  Total .nasl files:     {stats['total_files']:,}")
        console.print(f"  Sample size:           {stats['sampled']}")
        console.print(f"  Valid in sample:       {stats['valid_in_sample']}")
        console.print(f"  Estimated importable:  ~{stats['estimated_valid']:,}")
        console.print(f"  Plugin types:          {stats['plugin_types']}")
        console.print(f"\n  [bold]Top families:[/bold]")
        for family, count in stats["top_families"]:
            console.print(f"    {count:>5}  {family}")
        if stats.get("examples"):
            console.print(f"\n  [bold]Sample plugins:[/bold]")
            for ex in stats["examples"]:
                cves = ", ".join(ex["cves"]) if ex["cves"] else "no CVEs"
                console.print(f"    [{ex['severity']:8}] {ex['title'][:70]}  ({cves})")
        raise typer.Exit(code=0)

    # ---- Import mode --------------------------------------------------- #
    init_db()

    mode_label = "remote + combined" if remote_only else "all"
    console.print(f"[cyan]Importing[/cyan] {mode_label} plugins from [bold]{plugins_dir}[/bold]")
    console.print(f"[dim]Database:[/dim] {db_path}  |  [dim]Workers:[/dim] {importer.workers}")

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TaskProgressColumn(),
        console=console,
    ) as progress:
        task_id = progress.add_task("[cyan]Parsing & importing…", total=None)
        _total_ref: List[int] = [0]

        def _cb(done: int, total: int) -> None:
            if _total_ref[0] == 0:
                _total_ref[0] = total
                progress.update(task_id, total=total)
            progress.update(
                task_id,
                completed=done,
                description=f"[cyan]Importing…[/cyan] {done:,}/{total:,}",
            )

        try:
            stats = importer.run(plugins_dir, remote_only=remote_only, progress_callback=_cb)
        except Exception as exc:
            console.print(f"\n[red]Fatal error during import:[/red] {exc}")
            import traceback
            traceback.print_exc()
            raise typer.Exit(code=1)

    console.print(f"\n[bold green]Import complete![/bold green]")
    console.print(f"  [green]Imported:[/green]  {stats['imported']:,}")
    console.print(f"  [dim]Skipped:[/dim]   {stats['skipped']:,}")
    console.print(f"  [dim]Total:[/dim]     {stats['total']:,}")
    console.print(
        f"\n[dim]Run a scan to use these plugins — NASLAnalyzer loads them automatically.[/dim]"
    )
    return


if __name__ == "__main__":
    app()
