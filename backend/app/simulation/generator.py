"""Plan complete episodes, then merge independent ordered event streams."""

import heapq
import json
from dataclasses import dataclass
from random import Random
from uuid import NAMESPACE_URL, uuid5

from app.simulation.config import SimulationConfig
from app.simulation.constants import (
    CORE_SCENARIOS,
    GENERATOR_VERSION,
    OTHER_SCENARIOS,
    SCENARIO_WEIGHTS,
    Scenario,
)
from app.simulation.factory import EventFactory
from app.simulation.identities import create_profiles
from app.simulation.normal_activity import normal_session
from app.simulation.scenarios import BUILDERS, Episode, episode_sizes


@dataclass(frozen=True)
class EpisodePlan:
    scenario: Scenario
    size: int


def partition_count(total: int, sizes: tuple[int, ...]) -> list[int]:
    """Partition an exact request into whole episodes; never truncate scenario evidence."""
    smallest, largest = sizes[0], sizes[-1]
    if len(sizes) == largest - smallest + 1:
        episodes = (total + largest - 1) // largest
        if total >= episodes * smallest:
            base, extra = divmod(total, episodes)
            return [base + (i < extra) for i in range(episodes)]
    else:
        # Sparse password-spray sizes: reachability, bounded by the request (at most 1M).
        # bytearray avoids retaining a Python-int table for large requests.
        previous = bytearray(total + 1)
        for amount in range(1, total + 1):
            for size in sizes:
                if size > amount:
                    break
                if size == amount or previous[amount - size]:
                    previous[amount] = size  # sparse sizes are <=120
                    break
        if previous[total]:
            result = []
            while total:
                size = previous[total]
                result.append(size)
                total -= size
            return result
    raise ValueError(
        f"Requested count cannot form complete episodes (allowed sizes: {smallest}..{largest}). "
        "Omit --count for one episode, or choose a compatible count."
    )


class SecurityEventGenerator:
    def __init__(self, config: SimulationConfig | None = None):
        self.config = config or SimulationConfig()
        self.profiles = create_profiles(self.config)
        identity_config = self.config.model_dump(mode="json", exclude={"preset", "ground_truth"})
        identity_config["count"] = self.config.requested_count
        namespace = uuid5(
            NAMESPACE_URL,
            f"cybersentinel:simulation:{GENERATOR_VERSION}:"
            + json.dumps(identity_config, sort_keys=True, separators=(",", ":")),
        )
        self.factory = EventFactory(self.config, namespace)
        self.normal_count, self.episodes = self._plan()
        self.total_count = self.normal_count + sum(plan.size for plan in self.episodes)

    def _plan(self):
        cfg, rng = self.config, Random(f"{self.config.seed}:plan")
        count = cfg.requested_count
        if cfg.scenario == Scenario.NORMAL:
            return count, ()
        if cfg.scenario != Scenario.MIXED:
            sizes = episode_sizes(cfg.scenario, cfg)
            counts = [rng.choice(sizes)] if count is None else partition_count(count, sizes)
            rng.shuffle(counts)
            return 0, tuple(EpisodePlan(cfg.scenario, size) for size in counts)
        normal = int(count * cfg.normal_ratio + 0.5)
        remaining, result = count - normal, []
        candidates = CORE_SCENARIOS + OTHER_SCENARIOS
        sizes = {scenario: episode_sizes(scenario, cfg) for scenario in candidates}
        for scenario in candidates:
            minimum = sizes[scenario][0]
            if minimum <= remaining:
                result.append(EpisodePlan(scenario, minimum))
                remaining -= minimum
        while remaining:
            choices = [s for s in candidates if sizes[s][0] <= remaining]
            weights = [SCENARIO_WEIGHTS[candidates.index(s)] for s in choices]
            scenario = rng.choices(choices, weights=weights, k=1)[0]
            size = rng.choice([size for size in sizes[scenario] if size <= remaining])
            result.append(EpisodePlan(scenario, size))
            remaining -= size
        return normal, tuple(result)

    @property
    def omitted_scenarios(self):
        if self.config.scenario != Scenario.MIXED:
            return ()
        present = {plan.scenario for plan in self.episodes}
        return tuple(s for s in CORE_SCENARIOS + OTHER_SCENARIOS if s not in present)

    def _normal_streams(self):
        if not self.normal_count:
            return
        slots = min(
            len(self.profiles) * self.config.days,
            max(min(len(self.profiles), self.normal_count // 6), self.normal_count // 10, 1),
        )
        base, extra = divmod(self.normal_count, slots)
        for index in range(slots):
            cycle, profile_index = divmod(index, len(self.profiles))
            day = (profile_index + cycle) % self.config.days
            yield normal_session(
                self.factory, self.profiles[profile_index], day, base + (index < extra)
            )

    def iter_records(self):
        streams = list(self._normal_streams())
        for number, plan in enumerate(self.episodes):
            episode = Episode(self.factory, plan.scenario, plan.size, number, self.profiles)
            streams.append(BUILDERS[plan.scenario](episode))
        # One pending event per user-day/scenario, not a list of the entire dataset.
        yield from heapq.merge(
            *streams, key=lambda record: (record.event.timestamp, record.event.event_id)
        )

    def iter_events(self):
        for record in self.iter_records():
            yield record.event
