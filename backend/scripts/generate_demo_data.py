"""Export fictional events without loading application settings or connecting to a database."""

import argparse
import sys
from pathlib import Path

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from pydantic import ValidationError  # noqa: E402

from app.simulation.config import SimulationConfig  # noqa: E402
from app.simulation.constants import PRESETS, Scenario  # noqa: E402
from app.simulation.exporter import export_events  # noqa: E402
from app.simulation.generator import SecurityEventGenerator  # noqa: E402


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    size = result.add_mutually_exclusive_group()
    size.add_argument(
        "--count", type=int, help="Exact event count; defaults to 1,000 for mixed/normal"
    )
    size.add_argument("--preset", choices=PRESETS, help="small=1,000; medium=10,000; large=100,000")
    result.add_argument("--seed", type=int, default=42)
    result.add_argument("--output", type=Path, help="Default: data/demo_events.<format>")
    result.add_argument(
        "--format", dest="output_format", choices=("jsonl", "json"), default="jsonl"
    )
    result.add_argument("--start-date", default="2026-09-26", help="UTC interval start, YYYY-MM-DD")
    result.add_argument("--days", type=int, default=7)
    result.add_argument("--scenario", choices=[s.value for s in Scenario], default="mixed")
    result.add_argument(
        "--normal-ratio", type=float, default=0.95, help="Normal fraction in mixed mode"
    )
    result.add_argument(
        "--run-id", default="demo", help="Change for an independent event-ID namespace"
    )
    result.add_argument(
        "--records-per-event",
        type=int,
        default=25,
        help="Sensitive-record batch size; use 1 for one record per log",
    )
    result.add_argument("--no-ground-truth", action="store_true", help="Omit raw_data.simulation")
    result.add_argument("--overwrite", action="store_true", help="Replace an existing output file")
    return result


def main(argv: list[str] | None = None) -> int:
    arguments = parser()
    options = vars(arguments.parse_args(argv))
    output_format = options.pop("output_format")
    output = options.pop("output") or Path(f"data/demo_events.{output_format}")
    overwrite = options.pop("overwrite")
    options["ground_truth"] = not options.pop("no_ground_truth")
    try:
        generator = SecurityEventGenerator(SimulationConfig(**options))
        summary = export_events(generator, output, output_format, overwrite=overwrite)
    except (ValueError, OSError, ValidationError) as exc:
        arguments.error(str(exc))
    print(summary.render(generator, output, output_format))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
