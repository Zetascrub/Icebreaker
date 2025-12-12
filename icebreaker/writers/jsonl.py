from __future__ import annotations
import json
from pathlib import Path
from typing import List
from icebreaker.core.models import RunContext, Service, Finding

class JSONLWriter:
    id = "jsonl"

    def write(self, ctx: RunContext, services: List[Service], findings: List[Finding]):
        out = Path(ctx.out_dir) / "findings.jsonl"
        with out.open("w", encoding="utf-8") as f:
            for item in findings:
                f.write(json.dumps(item.model_dump()) + "\n")
