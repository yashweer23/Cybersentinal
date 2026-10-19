"""Run stored-event detection with the existing environment and database settings."""

import argparse
import logging
import sys
from pathlib import Path

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from pydantic import ValidationError  # noqa: E402
from sqlalchemy.orm import Session  # noqa: E402

from app.config import get_settings  # noqa: E402
from app.core.errors import ServiceError  # noqa: E402
from app.database import build_engine  # noqa: E402
from app.detection.engine import DetectionEngine  # noqa: E402
from app.schemas.detection import DetectionRunRequest  # noqa: E402


def parser():
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--batch-size", type=int)
    result.add_argument("--until-empty", action="store_true")
    result.add_argument("--rule", help="Only this enabled rule; leaves processed flags unchanged")
    result.add_argument("--dry-run", action="store_true", help="Preview without database writes")
    result.add_argument(
        "--replay", action="store_true", help="Also evaluate previously processed events"
    )
    return result


def print_summary(result):
    print("CyberSentinel Detection Engine")
    for name, value in (
        ("Events evaluated", result.events_evaluated),
        ("Events processed", result.events_processed),
        ("Findings matched", result.findings_matched),
        ("Findings created", result.findings_created),
        ("Duplicate findings", result.duplicate_findings),
        ("Rules executed", result.rules_executed),
    ):
        print(f"{name}: {value:,}")
    print("Rule matches (including existing fingerprints):")
    for key, count in sorted(result.rule_matches.items()):
        print(f"  {key}: {count}")
    print(f"Events remaining: {result.unprocessed_events}")
    print(f"Duration: {result.duration_ms / 1000:.3f}s")
    rate = result.events_evaluated * 1000 / result.duration_ms if result.duration_ms else 0
    print(f"Throughput: {rate:,.1f} events/sec")
    print(f"Complete pass: {result.complete}; dry run: {result.dry_run}; replay: {result.replay}")
    if result.dry_run:
        print("Potential findings (first 20, no writes):")
        for finding in result.findings_preview:
            print(
                f"  {finding['title']} | confidence {finding['confidence']} | "
                f"{finding['fingerprint'][:12]}"
            )
    if result.selected_rule:
        print("Single-rule pass: processed flags retained until a full enabled-rule pass.")
    if result.error:
        print(result.error)


def main(argv=None):
    arguments = parser()
    args = arguments.parse_args(argv)
    try:
        options = DetectionRunRequest(**vars(args))
    except ValidationError:
        arguments.error("Use a batch size of 1–1000 and a rule ID such as CS-001")
    try:
        settings = get_settings()
    except ValidationError:
        print("Invalid environment configuration. Check the existing .env.")
        return 1
    if settings.app_env not in {"development", "test"}:
        print("The trusted local detection CLI requires APP_ENV=development or test.")
        return 1
    logging.basicConfig(level=settings.log_level, format="%(levelname)s %(name)s %(message)s")
    engine = build_engine(settings)
    try:
        with Session(engine) as session:
            result = DetectionEngine(session, settings).run(options)
        print_summary(result)
        return 0 if result.complete else 2
    except ServiceError as exc:
        if hasattr(exc, "result"):
            print_summary(exc.result)
        else:
            print(exc.detail)
        return 1
    finally:
        engine.dispose()


if __name__ == "__main__":
    raise SystemExit(main())
