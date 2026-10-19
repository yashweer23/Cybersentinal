"""Score detection findings using the existing trusted local development environment."""

import argparse
import json
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
from app.risk.engine import RiskScoringEngine  # noqa: E402
from app.schemas.risk import RiskRunRequest  # noqa: E402


def print_summary(result):
    print("CyberSentinel Risk Scoring Engine")
    for label, value in (
        ("Findings evaluated", result.findings_evaluated),
        ("Scores created", result.assessments_created),
        ("Scores updated", result.assessments_updated),
        ("Already scored", result.already_scored),
        ("Unchanged assessments", result.unchanged_assessments),
        ("Invalid findings", result.invalid_findings),
    ):
        print(f"{label}: {value:,}")
    print("Risk distribution (valid findings evaluated in this run):")
    for level, count in result.by_level.items():
        print(f"  {level}: {count}")
    print(f"Average Risk Score: {result.average_score:.2f}")
    print(f"Duration: {result.duration_ms:.3f} ms")
    print(f"Remaining unscored: {result.remaining_unscored}")
    print(f"Complete pass: {result.complete}; dry run: {result.dry_run}; rescore: {result.rescore}")
    for skipped in result.skipped:
        print(f"Skipped {skipped['finding_id']}: {skipped['reason']}")
    if result.dry_run:
        print("Potential scores and breakdowns (first 20, no database writes):")
        print(json.dumps(result.previews, indent=2, ensure_ascii=False))
    if result.error:
        print(result.error)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--finding")
    parser.add_argument("--rule")
    parser.add_argument("--batch-size", type=int)
    parser.add_argument("--until-empty", action="store_true")
    parser.add_argument("--reputation-source", choices=["local", "cached"], default="local")
    parser.add_argument("--rescore", action="store_true")
    parser.add_argument("--dry-run", action="store_true")
    try:
        options = RiskRunRequest(**vars(parser.parse_args(argv)))
    except ValidationError:
        parser.error("Use batch size 1–500, a rule such as CS-001 and a valid finding ID")
    try:
        settings = get_settings()
    except ValidationError:
        print("Invalid environment or risk policy; check the existing .env configuration")
        return 1
    if settings.app_env not in {"development", "test"}:
        print("The trusted local scoring CLI requires APP_ENV=development or test")
        return 1
    logging.basicConfig(level=settings.log_level, format="%(levelname)s %(name)s %(message)s")
    engine = build_engine(settings)
    try:
        with Session(engine) as session:
            result = RiskScoringEngine(session, settings).run(options)
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
