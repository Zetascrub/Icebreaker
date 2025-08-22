from __future__ import annotations
import csv, json
from pathlib import Path
from typing import List
from icebreaker.core.models import RunContext, Service, Finding

class CSVWriter:
    id = "csv"

    def write(self, ctx: RunContext, services: List[Service], findings: List[Finding]) -> None:
        out = Path(ctx.out_dir)
        out.mkdir(parents=True, exist_ok=True)

        # services.csv
        with (out / "services.csv").open("w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(["target", "port", "service", "server", "title"])
            for s in sorted(services, key=lambda x: (x.target, x.port, x.name or "")):
                meta = s.meta or {}
                w.writerow([
                    s.target,
                    s.port,
                    s.name or "",
                    meta.get("server", ""),
                    meta.get("title", ""),
                ])

        # findings.csv
        with (out / "findings.csv").open("w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(["severity", "target", "port", "title", "details_preview", "details_json", "tags"])
            for a in findings:
                # compact JSON for machine-readability
                details_json = json.dumps(a.details or {}, ensure_ascii=False, separators=(",", ":"))
                # human preview, single line, trimmed
                preview = ", ".join(f"{k}={v}" for k, v in (a.details or {}).items() if v is not None and v != "")
                preview = " ".join(str(preview).split())[:160]  # collapse whitespace/newlines, cap length
                tags = " ".join(a.tags or [])
                w.writerow([a.severity.upper(), a.target, a.port or "", a.title, preview, details_json, tags])
