"""Validated streaming export; failed writes never replace an existing dataset."""

import os
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime
from ipaddress import ip_address, ip_network
from pathlib import Path
from tempfile import NamedTemporaryFile
from uuid import UUID

from app.schemas.security_event import SecurityEventCreate
from app.simulation.constants import EventType, Scenario
from app.simulation.generator import SecurityEventGenerator

SAFE_NETWORKS = tuple(
    ip_network(cidr)
    for cidr in (
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "192.0.2.0/24",
        "198.51.100.0/24",
        "203.0.113.0/24",
    )
)


def validate_event(event: SecurityEventCreate) -> SecurityEventCreate:
    checked = SecurityEventCreate.model_validate(event.model_dump(mode="json"))
    EventType(checked.event_type)
    if not checked.event_id.startswith("EVT-"):
        raise ValueError("Synthetic event IDs must have an EVT- prefix")
    UUID(checked.event_id.removeprefix("EVT-"))
    for address in (checked.source_ip, checked.destination_ip):
        if address is None or not any(ip_address(address) in network for network in SAFE_NETWORKS):
            raise ValueError("Synthetic addresses must use private or documentation IPv4 ranges")
    if checked.raw_data.get("environment") != "simulation":
        raise ValueError("Missing simulation environment marker")
    return checked


@dataclass
class GenerationSummary:
    total: int = 0
    normal: int = 0
    scenarios: Counter = field(default_factory=Counter)
    event_types: Counter = field(default_factory=Counter)
    sensitive_records: Counter = field(default_factory=Counter)
    first_timestamp: datetime | None = None
    last_timestamp: datetime | None = None

    def render(self, generator: SecurityEventGenerator, path: Path, output_format: str) -> str:
        rows = [
            "CyberSentinel Synthetic Security Data",
            f"Generated: {self.total:,} events",
            f"Normal events: {self.normal:,} ({self.normal / self.total:.1%})",
            f"Suspicious scenario events: {self.total - self.normal:,}",
            "Scenario event counts:",
        ]
        rows.extend(f"  {name}: {count:,}" for name, count in sorted(self.scenarios.items()))
        rows.append(
            "Event types: "
            + ", ".join(f"{name}={n}" for name, n in sorted(self.event_types.items()))
        )
        rows.append(
            "Sensitive records (separate from log count): "
            + ", ".join(f"{name}={n:,}" for name, n in sorted(self.sensitive_records.items()))
        )
        if generator.omitted_scenarios:
            rows.append(
                "Not included in this mixed event budget: "
                + ", ".join(s.value for s in generator.omitted_scenarios)
            )
        rows.extend(
            [
                f"UTC range: {self.first_timestamp.isoformat()} "
                f"to {self.last_timestamp.isoformat()}",
                f"Output ({output_format}): {path}",
                f"Seed: {generator.config.seed}",
                f"Run ID: {generator.config.run_id}",
                f"Ground truth: {'included' if generator.config.ground_truth else 'omitted'}",
            ]
        )
        return "\n".join(rows)


def export_events(
    generator: SecurityEventGenerator,
    output: str | Path,
    output_format: str = "jsonl",
    *,
    overwrite: bool = False,
) -> GenerationSummary:
    if output_format not in {"json", "jsonl"}:
        raise ValueError("Output format must be json or jsonl")
    output = Path(output)
    if output.suffix.lower() != f".{output_format}":
        raise ValueError(f"Use a .{output_format} output filename with --format {output_format}")
    if output.exists() and not overwrite:
        raise ValueError(f"Output already exists: {output}. Choose another path or --overwrite.")
    output.parent.mkdir(parents=True, exist_ok=True)
    summary = GenerationSummary()
    temporary = None
    try:
        with NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            newline="\n",
            dir=output.parent,
            prefix=".cybersentinel-",
            suffix=".tmp",
            delete=False,
        ) as handle:
            temporary = Path(handle.name)
            if output_format == "json":
                handle.write("[\n")
            previous = None
            for record in generator.iter_records():
                event = validate_event(record.event)
                order_key = event.timestamp, event.event_id
                if previous is not None and order_key < previous:
                    raise ValueError("Event stream is not chronologically ordered")
                if not generator.config.start <= event.timestamp < generator.config.end:
                    raise ValueError("Event timestamp lies outside the requested interval")
                previous = order_key
                if output_format == "json" and summary.total:
                    handle.write(",\n")
                handle.write(event.model_dump_json())
                if output_format == "jsonl":
                    handle.write("\n")
                summary.total += 1
                summary.normal += record.scenario == Scenario.NORMAL
                summary.scenarios[record.scenario.label] += 1
                summary.event_types[event.event_type] += 1
                if event.event_type == EventType.SENSITIVE_RECORD_ACCESS:
                    summary.sensitive_records[record.scenario.label] += event.raw_data[
                        "record_count"
                    ]
                summary.first_timestamp = summary.first_timestamp or event.timestamp
                summary.last_timestamp = event.timestamp
            if summary.total != generator.total_count:
                raise ValueError("Generated count differs from the requested count")
            if output_format == "json":
                handle.write("\n]\n")
        os.replace(temporary, output)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
    return summary
