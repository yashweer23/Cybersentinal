from dataclasses import dataclass
from random import Random

from app.simulation.config import SimulationConfig
from app.simulation.constants import OFFICES, USER_AGENTS, Location


@dataclass(frozen=True)
class UserProfile:
    """Monitored fictional identities, never rows in the application's users table."""

    username: str
    role: str
    location: Location
    internal_ip: str
    normal_start_minute: int
    normal_end_minute: int
    typical_devices: tuple[str, ...]
    typical_services: tuple[str, ...]
    user_agent: str

    @property
    def normal_start_hour(self) -> int:
        return self.normal_start_minute // 60

    @property
    def normal_end_hour(self) -> int:
        return self.normal_end_minute // 60 + 1


def create_profiles(config: SimulationConfig) -> tuple[UserProfile, ...]:
    rng = Random(f"cybersentinel-profiles-v1:{config.seed}")
    profiles = []
    for prefix, role, count in (
        ("employee", "employee", config.employee_count),
        ("manager", "manager", config.manager_count),
        ("analyst", "analyst", config.analyst_count),
        ("admin", "administrator", config.administrator_count),
    ):
        for number in range(1, count + 1):
            office = OFFICES[rng.randrange(len(OFFICES))]
            index = len(profiles) + 1
            devices = (f"LT-{office.code}-{index:03}", f"WS-{office.code}-{index:03}")
            start = rng.randint(config.working_start_hour * 60 + 35, 10 * 60 + 45)
            end = rng.randint(17 * 60 + 10, config.working_end_hour * 60 - 15)
            profiles.append(
                UserProfile(
                    username=f"{prefix}{number:03}",
                    role=role,
                    location=office,
                    internal_ip=f"10.0.{1 + (index - 1) // 240}.{1 + (index - 1) % 240}",
                    normal_start_minute=start,
                    normal_end_minute=end,
                    typical_devices=devices,
                    typical_services=("employee-portal", "records-api", "internal-api"),
                    user_agent=USER_AGENTS[rng.randrange(len(USER_AGENTS))],
                )
            )
    return tuple(profiles)
