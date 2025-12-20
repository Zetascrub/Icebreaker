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

# Import command subapp
import_app = typer.Typer(help="Import vulnerability data from external sources")
app.add_typer(import_app, name="import")


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
    use_nmap: bool = typer.Option(False, "--nmap", help="Use Nmap for faster scanning (10-100x speedup, requires nmap installed)"),
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
    # Use Nmap if requested and available, otherwise fall back to TCPProbe
    if use_nmap:
        try:
            from icebreaker.detectors.nmap_probe import NmapProbe
            detectors = [
                NmapProbe(timeout=timeout, quiet=quiet, ports=port_list),
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
        DNSAnalyzer(),          # DNS reconnaissance
        APIDiscovery(),         # API endpoint discovery
        WAFCDNDetector(),       # WAF and CDN detection
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


@import_app.command("nessus")
def import_nessus(
    plugin_archive: str = typer.Argument(..., help="Path to Nessus plugin archive (.tar, .tar.gz, .tgz)"),
    db_path: str = typer.Option("data/icebreaker.db", "--db", help="Path to database file"),
    preview_only: bool = typer.Option(False, "--preview", help="Preview only, don't import"),
    sample_size: int = typer.Option(20, "--sample", help="Number of plugins to preview"),
):
    """
    Import Nessus plugins from a tar archive.

    NOTE: This feature is currently disabled as it requires the FindingTemplate model which has been removed.
    Use the Plugin system instead for custom vulnerability checks.

    Example:
      icebreaker import nessus all-2.0.tar.gz
      icebreaker import nessus plugins.tar.gz --preview --sample 50
    """
    console.print("[red]Error:[/red] Nessus plugin import is currently disabled.")
    console.print("[yellow]Info:[/yellow] The FindingTemplate feature has been removed in favor of the Plugin system.")
    console.print("[yellow]Hint:[/yellow] Use the web interface to create custom plugins or add them via the API.")
    console.print("See docs/PLUGIN_SYSTEM.md for more information.")
    raise typer.Exit(code=1)

    # Disabled code below - kept for reference
    """
    try:
        from icebreaker.importers.nasl_parser import NASLParser
        from icebreaker.db.database import SessionLocal, engine
        from icebreaker.db.models import Base
    except ImportError as e:
        console.print(f"[red]Error:[/red] Missing dependencies: {e}")
        console.print("[yellow]Hint:[/yellow] Make sure the database and importer modules are available")
        raise typer.Exit(code=1)

    # Validate file exists
    archive_path = Path(plugin_archive)
    if not archive_path.exists():
        console.print(f"[red]Error:[/red] File not found: {plugin_archive}")
        raise typer.Exit(code=1)

    # Validate file type
    valid_extensions = ['.tar', '.tar.gz', '.tgz', '.tar.bz2']
    if not any(str(archive_path).endswith(ext) for ext in valid_extensions):
        console.print(f"[red]Error:[/red] Invalid file type. Must be one of: {', '.join(valid_extensions)}")
        raise typer.Exit(code=1)

    console.print(f"[cyan]Importing Nessus plugins from:[/cyan] {plugin_archive}")

    temp_dir = None
    try:
        # Create temporary directory
        temp_dir = tempfile.mkdtemp(prefix='nessus_import_')
        temp_path = Path(temp_dir)

        # Extract tar file
        console.print("[cyan]Extracting archive...[/cyan]")
        extract_dir = temp_path / 'extracted'
        extract_dir.mkdir()

        try:
            with tarfile.open(archive_path, 'r:*') as tar:
                # Security check: ensure no path traversal
                for member in tar.getmembers():
                    if member.name.startswith('/') or '..' in member.name:
                        continue
                    tar.extract(member, extract_dir)
        except tarfile.ReadError as e:
            console.print(f"[red]Error:[/red] Invalid tar archive: {e}")
            console.print("[yellow]Note:[/yellow] If this is an encrypted Nessus plugin feed, you need to decrypt it first using 'nessuscli update'")
            raise typer.Exit(code=1)

        # Find all .nasl files
        nasl_files = list(extract_dir.rglob('*.nasl'))
        total_files = len(nasl_files)

        if total_files == 0:
            console.print("[red]Error:[/red] No .nasl files found in archive")
            raise typer.Exit(code=1)

        console.print(f"[green]Found {total_files} NASL plugin files[/green]")

        # Preview mode
        if preview_only:
            console.print(f"[cyan]Previewing {min(sample_size, total_files)} plugins...[/cyan]")
            parser = NASLParser()

            # Sample files
            import random
            sample_files = random.sample(nasl_files, min(sample_size, total_files))

            valid_count = 0
            for nasl_file in sample_files:
                metadata = parser.parse_file(str(nasl_file))
                if metadata and metadata.get('title'):
                    valid_count += 1
                    template = parser.to_finding_template(metadata)
                    console.print(f"  [green]✓[/green] {template['title']} [{template['severity']}]")

            console.print(f"\n[cyan]Preview Summary:[/cyan]")
            console.print(f"  Valid plugins: {valid_count}/{len(sample_files)}")
            console.print(f"  Estimated total valid: ~{int((valid_count/len(sample_files)) * total_files)}")
            raise typer.Exit(code=0)

        # Import mode
        console.print("[cyan]Initializing database...[/cyan]")
        Base.metadata.create_all(bind=engine)
        db = SessionLocal()

        parser = NASLParser()
        imported = 0
        updated = 0
        skipped = 0
        errors = []

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            console=console,
        ) as progress:
            task = progress.add_task("[cyan]Importing plugins...", total=total_files)

            for nasl_file in nasl_files:
                try:
                    # Parse NASL file
                    metadata = parser.parse_file(str(nasl_file))

                    if not metadata or not metadata.get('title'):
                        skipped += 1
                        progress.update(task, advance=1)
                        continue

                    # Convert to template format
                    template_data = parser.to_finding_template(metadata)

                    # Check if already exists
                    existing = db.query(FindingTemplate).filter(
                        FindingTemplate.finding_id == template_data['finding_id']
                    ).first()

                    if existing:
                        # Update existing
                        for key, value in template_data.items():
                            if hasattr(existing, key) and value is not None:
                                setattr(existing, key, value)
                        updated += 1
                    else:
                        # Create new
                        template = FindingTemplate(**template_data)
                        db.add(template)
                        imported += 1

                    # Commit in batches of 100
                    if (imported + updated) % 100 == 0:
                        db.commit()

                except Exception as e:
                    error_msg = f"Error processing {nasl_file.name}: {str(e)}"
                    errors.append(error_msg)
                    if len(errors) <= 5:  # Only show first 5 errors
                        console.print(f"[yellow]Warning:[/yellow] {error_msg}")

                progress.update(task, advance=1)

        # Final commit
        db.commit()
        db.close()

        # Summary
        console.print(f"\n[bold green]Import Complete![/bold green]")
        console.print(f"  [green]New templates:[/green] {imported}")
        console.print(f"  [yellow]Updated templates:[/yellow] {updated}")
        console.print(f"  [dim]Skipped:[/dim] {skipped}")
        if errors:
            console.print(f"  [red]Errors:[/red] {len(errors)}")

    except typer.Exit:
        raise
    except Exception as e:
        console.print(f"[red]Fatal error:[/red] {e}")
        import traceback
        traceback.print_exc()
        raise typer.Exit(code=1)
    finally:
        # Cleanup temporary directory
        if temp_dir and Path(temp_dir).exists():
            shutil.rmtree(temp_dir)


if __name__ == "__main__":
    app()
