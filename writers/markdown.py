from __future__ import annotations
from pathlib import Path
from typing import List, Dict
from icebreaker.core.models import RunContext, Service, Finding


class MarkdownWriter:
    id = "markdown"

    def write(self, ctx: RunContext, services: List[Service], findings: List[Finding]) -> None:
        path = Path(ctx.out_dir) / "summary.md"

        # Group services by target for a tidy layout
        by_target: Dict[str, List[Service]] = {}
        for s in services:
            by_target.setdefault(s.target, []).append(s)

        # Sort findings by target then severity
        sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        sorted_findings = sorted(
            findings, key=lambda x: (x.target, sev_order.get(x.severity, 9), x.port or 0, x.title)
        )

        lines: list[str] = []
        lines.append("# Icebreaker Summary\n")
        lines.append(f"Run: `{ctx.run_id}`  ")
        lines.append(f"Preset: `{ctx.preset}`  ")
        lines.append(f"Output: `{ctx.out_dir}`\n")

        # Services section
        lines.append("## Services\n")
        for tgt in sorted(by_target.keys()):
            lines.append(f"### {tgt}")
            lines.append("| Port | Service | Server | Title |")
            lines.append("|------|---------|--------|-------|")
            for s in sorted(by_target[tgt], key=lambda x: x.port):
                meta = s.meta or {}
                server = meta.get("server", "")
                title = meta.get("title", "")
                lines.append(f"| {s.port} | {s.name or ''} | {server} | {title} |")
            lines.append("")

        # Findings section
        lines.append("## Findings\n")
        if not sorted_findings:
            lines.append("_No findings from v0.1 analyzers._")
        else:
            lines.append("| Severity | Target | Port | Title | Details |")
            lines.append("|----------|--------|------|-------|---------|")
            for f in sorted_findings:
                det = ", ".join(
                    f"{k}={v}" for k, v in (f.details or {}).items() if v is not None and v != ""
                )
                lines.append(
                    f"| {f.severity} | {f.target} | {f.port or ''} | {f.title} | {det[:160]} |"
                )

        path.write_text("\n".join(lines), encoding="utf-8")
