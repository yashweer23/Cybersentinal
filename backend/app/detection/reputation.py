"""Independent documentation-only indicators; never imports the event generator."""

from dataclasses import dataclass
from datetime import datetime
from ipaddress import ip_address
from typing import Protocol


@dataclass(frozen=True)
class Reputation:
    score: int
    source: str
    synthetic: bool
    expires_at: datetime | None = None
    context: dict | None = None


class ReputationProvider(Protocol):
    def lookup_ip(self, ip: str) -> Reputation | None: ...


class LocalSyntheticReputationProvider:
    INDICATORS = frozenset({"192.0.2.44", "198.51.100.73", "203.0.113.18"})

    def lookup_ip(self, ip):
        try:
            canonical = str(ip_address(ip))
        except ValueError:
            return None
        if canonical in self.INDICATORS:
            return Reputation(92, "Local synthetic development indicators", True)
        return None
