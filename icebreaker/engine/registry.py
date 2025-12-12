from __future__ import annotations
from typing import Protocol, Iterable, List
from icebreaker.core.models import RunContext, Target, Service, Finding

class Detector(Protocol):
    id: str
    async def run(self, ctx: RunContext, targets: list[Target]) -> Iterable[Service]: ...

class Analyzer(Protocol):
    id: str
    consumes: list[str]
    async def run(self, ctx: RunContext, service: Service) -> List[Finding]: ...

class Writer(Protocol):
    id: str
    def write(self, ctx: RunContext, services: List[Service], findings: List[Finding]) -> None: ...
