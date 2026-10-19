"""Development-only pipeline and performance validation in a disposable random schema.

Uses real migrations, services and HTTP routes. Never touches public application
rows. External intelligence is mocked, AI uses fallback, and credentials are random.
Optional JMeter targets only the temporary loopback server, with a token in its environment.
"""

import argparse
import csv
import json
import math
import os
import secrets
import statistics
import subprocess
import tempfile
import threading
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path
from time import perf_counter
from unittest.mock import patch

import httpx
import uvicorn
from fastapi.testclient import TestClient
from sqlalchemy import select, text
from sqlalchemy.orm import Session
from sqlalchemy.pool import QueuePool

from alembic import command
from app.ai.service import AIAnalystService
from app.config import get_settings
from app.core.enums import UserRole
from app.detection.engine import DetectionEngine
from app.incidents.engine import IncidentManagementService
from app.incidents.workflow import IncidentWorkflow
from app.main import create_app
from app.models import Incident, User
from app.risk.engine import RiskScoringEngine
from app.schemas.analytics import AnalyticsQuery
from app.schemas.detection import DetectionRunRequest
from app.schemas.incident import (
    AssignmentRequest,
    CommentRequest,
    IncidentRunRequest,
    StatusRequest,
)
from app.schemas.risk import RiskRunRequest
from app.security.passwords import hash_password
from app.services.event_files import ingest_file
from app.services.event_ingestion import EventIngestionService
from app.services.security_analytics import SecurityAnalyticsService
from app.simulation.config import SimulationConfig
from app.simulation.exporter import export_events
from app.simulation.generator import SecurityEventGenerator
from app.threat_intelligence.schemas import EnrichRequest
from app.threat_intelligence.service import ThreatIntelligenceService
from scripts.seed_detection_rules import seed_detection_rules
from tests.database_fixtures import isolated_schema, migration_config

ROOT = Path(__file__).resolve().parents[2]
TABLES = (
    "security_events",
    "detection_findings",
    "risk_assessments",
    "incidents",
    "incident_findings",
    "incident_evidence",
    "incident_processing",
)
ENDPOINTS = [
    "/api/dashboard/overview?range=7d",
    "/api/dashboard/events/recent?range=7d",
    "/api/dashboard/events/updates?after_id=0&limit=20",
    "/api/incidents?limit=20",
    "/api/detections?limit=20",
    "/api/analytics/overview?range=7d",
    "/api/analytics/events/trend?range=7d",
    "/api/analytics/detections/rules?range=7d",
    "/api/reports/incidents?format=csv&range=7d&limit=100",
    "/api/reports/security-summary?range=7d",
]


def timings(samples):
    ordered = sorted(samples)
    return {
        "samples": len(samples),
        "mean_ms": round(statistics.mean(samples), 3),
        "median_ms": round(statistics.median(samples), 3),
        "p95_ms": round(ordered[math.ceil(0.95 * len(ordered)) - 1], 3),
        "min_ms": round(ordered[0], 3),
        "max_ms": round(ordered[-1], 3),
    }


def counts(session):
    return {name: session.scalar(text(f"SELECT count(*) FROM {name}")) for name in TABLES}


def event_digest(session):
    # Hash each row in SQL first: only compact hashes enter the aggregate.
    return session.scalar(
        text("""
        SELECT md5(string_agg(digest, '' ORDER BY event_id)) FROM
        (SELECT event_id, md5((to_jsonb(e)-'processed')::text) digest FROM security_events e) rows
    """)
    )


def measured(result, name, action, count=None):
    started = perf_counter()
    value = action()
    elapsed = perf_counter() - started
    item = {"wall_ms": round(elapsed * 1000, 3)}
    if hasattr(value, "model_dump"):
        item["result"] = value.model_dump(mode="json")
    if count is not None:
        item["events_per_second"] = round(count / elapsed, 2)
    result[name] = item
    print(f"{name}: {item['wall_ms']:.3f} ms", flush=True)
    return value


def check_integrity(session):
    checks = {
        "finding_event_references": """SELECT count(*) FROM detection_findings f,
          LATERAL jsonb_array_elements_text(f.evidence_event_ids) ids(value)
          LEFT JOIN security_events e ON e.event_id=ids.value WHERE e.id IS NULL""",
        "incident_event_references": """SELECT count(*) FROM incident_evidence ie
          LEFT JOIN security_events e ON e.id=ie.security_event_id WHERE e.id IS NULL""",
        "incident_finding_references": """SELECT count(*) FROM incident_findings l
          LEFT JOIN incidents i ON i.id=l.incident_id
          LEFT JOIN detection_findings f ON f.id=l.detection_finding_id
          WHERE i.id IS NULL OR f.id IS NULL""",
        "assessment_references": """SELECT count(*) FROM risk_assessments a
          LEFT JOIN detection_findings f ON f.id=a.detection_finding_id WHERE f.id IS NULL""",
        "duplicate_fingerprints": ("SELECT count(*)-count(DISTINCT fingerprint) "
                                  "FROM detection_findings"),
        "duplicate_incident_links": """SELECT count(*)-count(DISTINCT detection_finding_id)
          FROM incident_findings""",
        "invalid_risk": ("SELECT count(*) FROM risk_assessments "
                         "WHERE risk_score NOT BETWEEN 0 AND 100"),
    }
    result = {name: session.scalar(text(sql)) for name, sql in checks.items()}
    assert not any(result.values()), result
    return result


def http_checks(app, password, identifier, samples):
    with TestClient(app, base_url="http://localhost") as client:
        response = client.post(
            "/api/auth/login",
            json={"username": "validationadmin", "password": password},
            headers={"X-CSRF-Guard": "1"},
        )
        assert response.status_code == 200
        headers = {"Authorization": "Bearer " + response.json()["access_token"]}
        results = {}
        for path in [*ENDPOINTS, f"/api/incidents/{identifier}"]:
            response = client.get(path, headers=headers)
            assert response.status_code == 200, (path, response.status_code)
            elapsed = []
            for _ in range(samples):
                started = perf_counter()
                response = client.get(path, headers=headers)
                elapsed.append((perf_counter() - started) * 1000)
                assert response.status_code == 200
            results[path] = {**timings(elapsed), "response_bytes": len(response.content)}
        spec = client.get("/openapi.json").json()
        operations = [
            v["operationId"]
            for p in spec["paths"].values()
            for v in p.values()
            if "operationId" in v
        ]
        assert len(operations) == len(set(operations))
        assert client.get("/docs").status_code == 200
        assert client.get("/api/system/ready").status_code == 200
        assert all(client.get(path).status_code == 401 for path in ENDPOINTS)
        return {
            "latencies": results,
            "openapi_operations": len(operations),
            "anonymous_denied": True,
        }


def load_test(app, password, args):
    server = uvicorn.Server(
        uvicorn.Config(
            app,
            host="127.0.0.1",
            port=args.port,
            log_level="warning",
            access_log=False,
            proxy_headers=False,
        )
    )
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    try:
        for _ in range(100):
            if server.started:
                break
            if not thread.is_alive():
                raise RuntimeError("Validation server could not bind the loopback port")
            time.sleep(0.1)
        assert server.started
        with httpx.Client(base_url=f"http://127.0.0.1:{args.port}", trust_env=False) as client:
            response = client.post(
                "/api/auth/login",
                json={"username": "validationadmin", "password": password},
                headers={"X-CSRF-Guard": "1"},
            )
            assert response.status_code == 200
            token = response.json()["access_token"]
            assert (
                client.get("/api/auth/me", headers={"Authorization": "Bearer " + token}).status_code
                == 200
            )
        directory = args.output.parent / f"load-{args.load_users}-{secrets.token_hex(4)}"
        directory.mkdir(parents=True)
        jtl = directory / "samples.csv"
        env = {**os.environ, "JMETER_ACCESS_TOKEN": token}
        command_line = [
            str(args.jmeter.resolve()),
            "-n",
            "-t",
            str(ROOT / "tests/performance/read_only.jmx"),
            f"-Jport={args.port}",
            f"-Jusers={args.load_users}",
            f"-Jseconds={args.load_seconds}",
            "-l",
            str(jtl.resolve()),
            "-j",
            str((directory / "jmeter.log").resolve()),
            "-e",
            "-o",
            str((directory / "html").resolve()),
        ]
        completed = subprocess.run(
            command_line, env=env, check=False, timeout=args.load_seconds + 120
        )
        assert completed.returncode == 0, "JMeter failed; inspect its log"
        with jtl.open(newline="", encoding="utf-8-sig") as stream:
            rows = list(csv.DictReader(stream))
        assert rows, "JMeter produced no samples"
        errors = sum(r["success"].lower() != "true" for r in rows)
        by_endpoint = {}
        for label in sorted({r["label"] for r in rows}):
            group = [r for r in rows if r["label"] == label]
            by_endpoint[label] = {
                **timings([float(r["elapsed"]) for r in group]),
                "errors": sum(r["success"].lower() != "true" for r in group),
            }
        result = {
            "users": args.load_users,
            "scheduled_seconds": args.load_seconds,
            "samples": len(rows),
            "errors": errors,
            "endpoints": by_endpoint,
            "jtl": str(jtl),
            "report": str(directory / "html"),
            "tool": "Apache JMeter 5.6.3",
        }
        assert errors == 0, result
        return result
    finally:
        server.should_exit = True
        thread.join(timeout=15)


def validate(args):
    settings = get_settings()
    if settings.app_env not in {"development", "test"}:
        raise ValueError("Validation requires APP_ENV=development or test")
    settings = settings.model_copy(
        update={
            "app_env": "test",
            "auth_rate_limit_enabled": True,
            "log_level": "WARNING",
            "threat_intelligence_mock_mode": True,
            "ai_provider": "fallback",
            "jwt_secret_key": type(settings.jwt_secret_key)(secrets.token_urlsafe(48)),
        }
    )
    for field in ("ai_api_key", "abuseipdb_api_key", "virustotal_api_key", "otx_api_key"):
        setattr(settings, field, type(getattr(settings, field))(""))
    url = os.environ.get("TEST_DATABASE_URL") or settings.database_url
    result = {
        "created_at": datetime.now(UTC).isoformat(),
        "count": args.count,
        "seed": 42,
        "scenario": "mixed",
        "external_providers": "mock",
        "steps": {},
        "db_pool_size": args.db_pool_size,
        "measurement_note": ("Serial TestClient timings include serialization; "
                             "JMeter uses loopback TCP."),
    }
    with isolated_schema(
        url, poolclass=QueuePool, pool_size=args.db_pool_size, max_overflow=0
    ) as engine:
        with engine.begin() as conn:
            result["database_version"] = conn.scalar(text("SELECT version()"))
            command.upgrade(migration_config(conn), "head")
            command.check(migration_config(conn))
        password = secrets.token_urlsafe(24) + "!a1A"
        with Session(engine) as session:
            seed_detection_rules(session)
            for role in UserRole:
                session.add(
                    User(
                        username="validation" + role.value.lower(),
                        email=role.value.lower() + "@validation.example.test",
                        role=role,
                        hashed_password=hash_password(password),
                    )
                )
            session.commit()
        start = (datetime.now(UTC) - timedelta(days=7)).date()
        result["start_date"] = start.isoformat()
        with (
            tempfile.TemporaryDirectory(prefix="cs-validation-") as directory,
            Session(engine) as session,
        ):
            target = Path(directory) / "events.jsonl"
            config = SimulationConfig(count=args.count, seed=42, scenario="mixed", start_date=start)
            measured(
                result["steps"],
                "generate",
                lambda: export_events(SecurityEventGenerator(config), target, "jsonl"),
            )
            ingestion = EventIngestionService(session, settings)
            inserted = measured(
                result["steps"], "ingest", lambda: ingest_file(ingestion, target), args.count
            )
            assert inserted.inserted == args.count and inserted.invalid == inserted.failed == 0
            original = event_digest(session)
            detection = measured(
                result["steps"],
                "detect",
                lambda: DetectionEngine(session, settings).run(
                    DetectionRunRequest(until_empty=True)
                ),
                args.count,
            )
            assert detection.complete and detection.events_processed == args.count
            assert detection.rules_executed == 10 and detection.findings_created > 0
            assert session.scalar(text("SELECT count(*) FROM incidents")) == 0
            scoring = measured(
                result["steps"],
                "risk",
                lambda: RiskScoringEngine(session, settings).run(RiskRunRequest(until_empty=True)),
            )
            assert scoring.complete and scoring.assessments_created == detection.findings_created
            cases = measured(
                result["steps"],
                "incidents",
                lambda: IncidentManagementService(session, settings).run(
                    IncidentRunRequest(until_empty=True)
                ),
            )
            assert cases.complete and cases.incidents_created > 0
            before = counts(session)
            duplicate = measured(
                result["steps"], "ingest_repeat", lambda: ingest_file(ingestion, target)
            )
            assert duplicate.inserted == 0 and duplicate.duplicates == args.count
            replay = measured(
                result["steps"],
                "detect_replay",
                lambda: DetectionEngine(session, settings).run(
                    DetectionRunRequest(until_empty=True, replay=True)
                ),
            )
            assert replay.complete and replay.findings_created == 0
            risk_repeat = RiskScoringEngine(session, settings).run(RiskRunRequest(until_empty=True))
            case_repeat = IncidentManagementService(session, settings).run(
                IncidentRunRequest(until_empty=True)
            )
            assert risk_repeat.assessments_created == case_repeat.incidents_created == 0
            assert counts(session) == before and event_digest(session) == original
            result["counts"] = before
            result["idempotency"] = {
                "passed": True,
                "replay_duplicates": replay.duplicate_findings,
                "raw_events_unchanged": True,
            }
            result["integrity"] = check_integrity(session)
            assert (
                session.scalar(text("SELECT count(*) FROM security_events WHERE NOT processed"))
                == 0
            )
            result["unprocessed_events"] = 0
            result["rule_counts"] = [
                dict(r)
                for r in session.execute(
                    text("""
                SELECT r.rule_id, count(f.id) AS findings FROM detection_rules r
                LEFT JOIN detection_findings f ON f.detection_rule_id=r.id
                GROUP BY r.rule_id ORDER BY r.rule_id""")
                ).mappings()
            ]
            intel = ThreatIntelligenceService(session, settings, mock=True)
            offset = 0
            while True:
                enriched = measured(
                    result["steps"],
                    f"intelligence_{offset}",
                    lambda: intel.enrich_pending(
                        EnrichRequest(
                            limit=settings.threat_intelligence_max_incidents, offset=offset
                        )
                    ),
                )
                assert enriched.complete and enriched.external_lookups == 0
                if enriched.next_offset is None:
                    break
                assert enriched.next_offset > offset
                offset = enriched.next_offset
            incident = session.scalar(select(Incident).order_by(Incident.created_at, Incident.id))
            identifier = incident.incident_id
            analyst = session.scalar(select(User).where(User.role == UserRole.ANALYST))
            workflow = IncidentWorkflow(session)
            workflow.assign(identifier, AssignmentRequest(analyst_id=analyst.id), analyst)
            workflow.status(identifier, StatusRequest(status="INVESTIGATING"), analyst)
            workflow.comment(
                identifier,
                CommentRequest(comment="Synthetic validation: reviewed evidence."),
                analyst,
            )
            analysis = measured(
                result["steps"],
                "ai_fallback",
                lambda: AIAnalystService(session, settings).analyze_incident(
                    identifier, actor_id=analyst.id
                ),
            )
            assert analysis.analysis_mode == "FALLBACK"
            workflow.status(
                identifier,
                StatusRequest(
                    status="RESOLVED", resolution_summary="Synthetic validation complete."
                ),
                analyst,
            )
            query = AnalyticsQuery(
                start=datetime.combine(start, datetime.min.time(), UTC), end=datetime.now(UTC)
            )
            svc = SecurityAnalyticsService(session, settings)
            overview = svc.execute("overview", query)
            assert (
                overview.total_events == args.count
                and overview.incidents_created == cases.incidents_created
            )
            result["analytics"] = overview.model_dump(mode="json")
            result["evaluation"] = svc.execute("evaluation", query).model_dump(mode="json")
            session.commit()
        with engine.begin() as conn:
            command.upgrade(migration_config(conn), "head")
            command.check(migration_config(conn))
            result["event_query_plan"] = conn.execute(
                text("""
                EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON)
                SELECT event_type,count(*) FROM security_events
                WHERE timestamp>=:start GROUP BY event_type
            """),
                {"start": datetime.combine(start, datetime.min.time(), UTC)},
            ).scalar()
        with Session(engine) as session:
            assert counts(session) == before and event_digest(session) == original
        result["clean_and_populated_migrations"] = "passed"
        with patch("app.main.build_engine", lambda _: engine):
            result["http"] = http_checks(create_app(settings), password, identifier, args.samples)
            args.output.parent.mkdir(parents=True, exist_ok=True)
            result["status"] = "pipeline_passed_load_pending" if args.jmeter else "passed"
            args.output.write_text(json.dumps(result, indent=2), encoding="utf-8")
            if args.jmeter:
                result["load"] = load_test(create_app(settings), password, args)
            result["status"] = "passed"
        args.output.write_text(json.dumps(result, indent=2), encoding="utf-8")
    print(f"Validation passed. Results: {args.output}")
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--count", type=int, choices=[1000, 10000], default=10000)
    parser.add_argument("--output", type=Path, default=Path("data/phase16-results.json"))
    parser.add_argument("--samples", type=int, choices=range(5, 101), default=20)
    parser.add_argument("--db-pool-size", type=int, choices=range(1, 21), default=5)
    parser.add_argument("--jmeter", type=Path, help="Path to jmeter or jmeter.bat")
    parser.add_argument("--load-users", type=int, choices=[10, 25], default=10)
    parser.add_argument("--load-seconds", type=int, choices=[30, 60], default=30)
    parser.add_argument("--port", type=int, default=18000)
    args = parser.parse_args(argv)
    if not 1024 <= args.port <= 65535:
        parser.error("Use an unprivileged loopback port from 1024 to 65535")
    validate(args)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
