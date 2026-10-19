from dataclasses import dataclass
from typing import Protocol


@dataclass
class ProviderResult:
    plan: object
    mode: str
    provider: str
    model: str | None = None
    failure: str | None = None
    retry_after_seconds: int | None = None
    duration_ms: float = 0


class AIProvider(Protocol):
    def is_configured(self) -> bool: ...
    def generate(self, catalog) -> ProviderResult: ...
