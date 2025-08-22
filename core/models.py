from __future__ import annotations
from pydantic import BaseModel, Field
from typing import Dict, List, Optional
from datetime import datetime
import uuid
from pathlib import Path


class Target(BaseModel):
    address: str
    labels: Dict[str, str] = Field(default_factory=dict)


class Service(BaseModel):
    target: str              # Target.address
    port: int
    proto: str = "tcp"
    name: Optional[str] = None
    meta: Dict[str, str] = Field(default_factory=dict)


class Finding(BaseModel):
    id: str
    title: str
    severity: str            # INFO, LOW, MEDIUM, HIGH, CRITICAL
    target: str
    port: Optional[int] = None
    tags: List[str] = Field(default_factory=list)
    details: Dict[str, str] = Field(default_factory=dict)
    references: List[str] = Field(default_factory=list)


class RunContext(BaseModel):
    run_id: str
    preset: str
    out_dir: str
    started_at: datetime
    settings: Dict[str, str] = Field(default_factory=dict)

    @property
    def out_path(self) -> Path:
        return Path(self.out_dir)

    @staticmethod
    def new(preset: str, out_dir: Optional[str] = None) -> "RunContext":
        rid = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ") + "-" + uuid.uuid4().hex[:6]
        base = Path(out_dir or f"runs/{rid}-{preset}")
        base.mkdir(parents=True, exist_ok=True)
        (base / "targets").mkdir(parents=True, exist_ok=True)
        return RunContext(run_id=rid, preset=preset, out_dir=str(base), started_at=datetime.utcnow())
