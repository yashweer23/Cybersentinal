"""Promote and correlate scored findings using trusted local development access."""

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
from app.incidents.engine import IncidentManagementService  # noqa: E402
from app.schemas.incident import IncidentRunRequest  # noqa: E402


def print_summary(result):
    print("CyberSentinel Incident Processing")
    for label, value in (
        ("Findings evaluated", result.findings_evaluated),
        ("Eligible findings", result.eligible_findings),
        ("Incidents created", result.incidents_created),
        ("Incidents updated", result.incidents_updated),
        ("Findings attached", result.findings_attached),
        ("Correlated findings", result.correlated_findings),
        ("Findings skipped", result.findings_skipped),
        ("Invalid findings", result.invalid_findings),
    ):
        print(f"{label}: {value:,}")
    print("Incident severity (distinct cases touched in this run):")
    for level, count in result.by_severity.items():
        print(f"  {level}: {count}")
    print(f"Duration: {result.duration_ms:.3f} ms")
    print(f"Remaining pending: {result.remaining}")
    print(f"Complete pass: {result.complete}; dry run: {result.dry_run}")
    if result.dry_run:
        print(f"Projected incidents: {result.projected_incidents_created}")
        print(f"Projected links: {result.projected_findings_attached}")
        print("Correlation decisions (first 20; read-only plan):")
        print(json.dumps([d.model_dump(mode="json") for d in result.decisions], indent=2))
    for skipped in result.skipped:
        print(f"Skipped {skipped['finding_id']}: {skipped['reason']}")
    if result.error:
        print(result.error)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--until-empty", action="store_true")
    parser.add_argument("--minimum-risk", type=int)
    parser.add_argument("--finding")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--batch-size", type=int)
    try:
        options = IncidentRunRequest(**vars(parser.parse_args(argv)))
    except ValidationError:
        parser.error("Use minimum risk 0–100, batch size 1–500 and a valid finding identifier")
    try:
        settings = get_settings()
    except ValidationError:
        print("Invalid environment; check the existing .env configuration")
        return 1
    if settings.app_env not in {"development", "test"}:
        print("The trusted local incident CLI requires APP_ENV=development or test")
        return 1
    logging.basicConfig(level=settings.log_level, format="%(levelname)s %(name)s %(message)s")
    engine = build_engine(settings)
    try:
        with Session(engine) as session:
            result = IncidentManagementService(session, settings).run(options)
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
