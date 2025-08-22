from __future__ import annotations
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field, field_serializer
from datetime import datetime, timezone
from uuid import uuid4
from pathlib import Path

class RunContext(BaseModel):
    run_id: str
    preset: str
    out_dir: str
    started_at: datetime
    settings: Dict[str, Any] = Field(default_factory=dict)

    @classmethod
    def new(cls, *, preset: str, out_dir: str | None = None, settings: Dict[str, Any] | None = None) -> "RunContext":
        now = datetime.now(timezone.utc)
        # e.g. 20250822T230656Z-d0c220
        run_id = f"{now.strftime('%Y%m%dT%H%M%SZ')}-{str(uuid4())[:6]}"
        if out_dir is None:
            out_dir = str(Path("runs") / f"{run_id}-{preset}")
        return cls(
            run_id=run_id,
            preset=preset,
            out_dir=out_dir,
            started_at=now,
            settings=settings or {},
        )

    @field_serializer("started_at")
    def _ser_started_at(self, dt: datetime, _info):
        # Always emit ISO 8601 with timezone
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.isoformat()

class Target(BaseModel):
    address: str
    labels: Dict[str, str] = Field(default_factory=dict)

class Service(BaseModel):
    target: str
    port: int
    name: Optional[str] = None
    meta: Dict[str, Any] = Field(default_factory=dict)  # allow ints/bools/etc.

class Finding(BaseModel):
    id: str
    title: str
    severity: str
    target: str
    port: Optional[int] = None
    tags: List[str] = Field(default_factory=list)
    details: Dict[str, Any] = Field(default_factory=dict)
