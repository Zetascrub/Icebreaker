from __future__ import annotations
from typing import Protocol, Iterable, List
from icebreaker.core.models import RunContext, Target, Service, Finding

class Detector(Protocol):
    id: str
    async def run(self, ctx: RunContext, targets: list[Target]) -> Iterable[Service]: ...

class Analyzer(Protocol):
    id: str
    consumes: list[str]  # e.g. ["service:http"]
    async def run(self, ctx: RunContext, service: Service) -> List[Finding]: ...
