"""Explicit local threat enrichment; defaults to the configured mock/live mode."""

import argparse
import json
import logging
import sys
from pathlib import Path

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from pydantic import ValidationError  # noqa: E402
from sqlalchemy.exc import SQLAlchemyError  # noqa: E402
from sqlalchemy.orm import Session  # noqa: E402

from app.config import get_settings  # noqa: E402
from app.core.errors import ServiceError  # noqa: E402
from app.database import build_engine  # noqa: E402
from app.threat_intelligence.schemas import EnrichRequest, LookupRequest  # noqa: E402
from app.threat_intelligence.service import ThreatIntelligenceService  # noqa: E402


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    target = parser.add_mutually_exclusive_group(required=True)
    target.add_argument("--ip")
    target.add_argument("--incident")
    target.add_argument("--finding")
    target.add_argument("--all", action="store_true")
    parser.add_argument("--limit", type=int, default=50)
    parser.add_argument("--offset", type=int, default=0)
    parser.add_argument("--force-refresh", action="store_true")
    parser.add_argument("--mock", action="store_true")
    args = parser.parse_args(argv)
    try:
        payload = (
            LookupRequest(ip=args.ip, force_refresh=args.force_refresh)
            if args.ip
            else EnrichRequest(
                incident_id=args.incident,
                limit=1 if args.incident else args.limit,
                offset=args.offset,
                force_refresh=args.force_refresh,
            )
        )
    except ValidationError:
        parser.error("Use a valid IP/identifier, limit 1–100 and a nonnegative offset")
    try:
        settings = get_settings()
    except ValidationError:
        print("Invalid environment configuration; check your local .env")
        return 1
    if settings.app_env not in {"development", "test"}:
        print("The trusted local enrichment CLI requires APP_ENV=development or test")
        return 1
    logging.basicConfig(level=settings.log_level, format="%(levelname)s %(name)s %(message)s")
    engine = build_engine(settings)
    try:
        with Session(engine) as session:
            service = ThreatIntelligenceService(session, settings, mock=True if args.mock else None)
            print(f"CyberSentinel Threat Intelligence — {service.mode.upper()} mode")
            if args.ip:
                result = service.lookup_ip(payload.ip, force_refresh=args.force_refresh)
            elif args.finding:
                result = service.enrich_finding(args.finding, force_refresh=args.force_refresh)
            else:
                result = service.enrich_pending(payload)
            print(json.dumps(result.model_dump(mode="json"), indent=2, ensure_ascii=False))
            return 0 if getattr(result, "complete", True) else 2
    except (ServiceError, SQLAlchemyError, ValueError) as exc:
        print(
            exc.detail
            if isinstance(exc, ServiceError)
            else "Enrichment failed; check database and configuration"
        )
        return 1
    finally:
        engine.dispose()


if __name__ == "__main__":
    raise SystemExit(main())
