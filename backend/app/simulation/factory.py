from dataclasses import dataclass
from datetime import UTC, datetime
from random import Random
from uuid import UUID, uuid5

from app.schemas.security_event import SecurityEventCreate
from app.simulation.config import SimulationConfig
from app.simulation.constants import GENERATOR_VERSION, SERVICES, EventType, Location, Scenario
from app.simulation.identities import UserProfile


@dataclass(frozen=True)
class GeneratedRecord:
    """Export bookkeeping around the existing schema, not a second event definition."""

    event: SecurityEventCreate
    scenario: Scenario
    scenario_id: str


class EventFactory:
    def __init__(self, config: SimulationConfig, namespace: UUID):
        self.config, self.namespace = config, namespace

    def scenario_id(self, key: str) -> str:
        return f"SIM-{uuid5(self.namespace, key)}"

    def make(
        self,
        *,
        key: str,
        scenario: Scenario,
        scenario_id: str,
        timestamp: datetime,
        user: UserProfile,
        event_type: EventType,
        rng: Random,
        service: str = "authentication",
        source_ip: str | None = None,
        destination_ip: str | None = None,
        destination_port: int | None = None,
        location: Location | None = None,
        raw: dict | None = None,
        status: str | None = None,
        device: str | None = None,
        user_agent: str | None = None,
    ) -> GeneratedRecord:
        event_type = EventType(event_type)
        target_ip, target_device, target_port = SERVICES[service]
        geo = location or user.location
        raw_data = {
            "environment": "simulation",
            "geo": {
                "city": geo.city,
                "country": geo.country,
                "latitude": geo.latitude,
                "longitude": geo.longitude,
            },
            "destination_device": target_device,
            **(raw or {}),
        }
        if self.config.ground_truth:
            raw_data["simulation"] = {
                "scenario": scenario.label,
                "scenario_id": scenario_id,
                "generator_version": GENERATOR_VERSION,
                "run_id": self.config.run_id,
            }
        default_status = {
            EventType.LOGIN_FAILED: "failed",
            EventType.MFA_FAILED: "failed",
            EventType.ACCESS_DENIED: "denied",
            EventType.ACCOUNT_LOCKED: "locked",
            EventType.MALWARE_ALERT: "quarantined",
        }.get(event_type, "success")
        # This is the same schema Phase 2 exposes to upstream producers.
        event = SecurityEventCreate(
            event_id=f"EVT-{uuid5(self.namespace, key)}",
            timestamp=timestamp.astimezone(UTC),
            source_ip=source_ip or user.internal_ip,
            destination_ip=destination_ip or target_ip,
            username=user.username,
            event_type=event_type.value,
            service=service,
            source_port=rng.randint(49152, 65535),
            destination_port=target_port if destination_port is None else destination_port,
            country=geo.country,
            device=device or user.typical_devices[0],
            user_agent=user_agent or user.user_agent,
            status=status or default_status,
            raw_data=raw_data,
        )
        if not self.config.start <= event.timestamp < self.config.end:
            raise ValueError("Generator produced a timestamp outside its configured interval")
        return GeneratedRecord(event, scenario, scenario_id)


def record_batch(scenario_id: str, offset: int, count: int) -> dict:
    prefix = scenario_id.removeprefix("SIM-").replace("-", "")
    identifiers = [f"REC-{prefix}-{i:06}" for i in range(offset + 1, offset + count + 1)]
    return {
        "resource_type": "patient_record",
        "department": "simulated",
        "sensitive": True,
        "record_id": identifiers[0],
        "record_ids": identifiers,
        "record_count": count,
    }
