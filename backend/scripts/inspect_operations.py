"""Read-only business-table counts for restart/persistence checks; no credential output."""

import json

from sqlalchemy import text

from app.config import get_settings
from app.database import build_engine

# Authentication creates sessions/audit entries, so exclude those changing operational records.
TABLES = (
    "users",
    "security_events",
    "detection_rules",
    "detection_findings",
    "risk_assessments",
    "incidents",
    "incident_evidence",
    "incident_comments",
    "threat_intelligence",
    "threat_intelligence_results",
    "incident_findings",
    "incident_processing",
    "ai_analyses",
)


def main():
    engine = build_engine(get_settings())
    try:
        with engine.connect() as connection:
            counts = {
                name: connection.scalar(text(f'SELECT count(*) FROM "{name}"')) for name in TABLES
            }
        print(json.dumps(counts, sort_keys=True))
    finally:
        engine.dispose()


if __name__ == "__main__":
    main()
