from __future__ import annotations
from pathlib import Path
from typing import List, Dict
from icebreaker.core.models import RunContext, Service, Finding

class MarkdownWriter:
    id = "markdown"

    def write(self, ctx: RunContext, services: List[Service], findings: List[Finding]):
        path = Path(ctx.out_dir) / "summary.md"
        by_target: Dict[str, List[Service]] = {}
        for s in services:
            by_target.setdefault(s.target, []).append(s)
        sev_order = {"CRITICAL":0, "HIGH":1, "MEDIUM":2, "LOW":3, "INFO":4}
        sorted_findings = sorted(findings, key=lambda x: (x.target, sev_order.get(x.severity, 9)))

        lines: list[str] = []
        lines.append(f"# Icebreaker Summary\n")
        lines.append(f"Run: `{ctx.run_id}`  \nPreset: `{ctx.preset}`  \nOutput: `{ctx.out_dir}`\n")

        lines.append("## Services\n")
        for tgt, svcs in sorted(by_target.items()):
            lines.append(f"### {tgt}")
            lines.append("| Port | Service | Server | Title |")
            lines.append("|------|---------|--------|-------|")
            for s in sorted(svcs, key=lambda x: x.port):
                server = s.meta.get("server","")
                title = s.meta.get("title","")
                lines.append(f"| {s.port} | {s.name or ''} | {server} | {title} |")
            lines.append("")

        lines.append("## Findings\n")
        if not sorted_findings:
            lines.append("_No findings in v0.1 analyzers._")
        else:
            lines.append("| Severity | Target | Port | Title |")
            lines.append("|----------|--------|------|-------|")
            for f in sorted_findings:
                lines.append(f"| {f.severity} | {f.target} | {f.port or ''} | {f.title} |")
        path.write_text("\n".join(lines), encoding="utf-8")
