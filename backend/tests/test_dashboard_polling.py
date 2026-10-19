"""Insertion cursors cover late logs, duplicates, rollbacks and concurrent commits."""

from concurrent.futures import ThreadPoolExecutor, TimeoutError
from datetime import UTC, datetime, timedelta
from threading import Event
from uuid import uuid4

import pytest
from sqlalchemy import select, text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.orm import Session

from alembic import command
from app.models import SecurityEvent
from app.schemas.dashboard import RecentQuery, UpdatesQuery
from app.services.dashboard_service import DashboardService
from app.services.event_ingestion import EventIngestionService
from tests.database_fixtures import isolated_schema, migration_config
from tests.test_event_ingestion import http as http
from tests.test_event_ingestion import settings as settings
from tests.test_event_ingestion import tokens as tokens
from tests.test_event_ingestion_unit import event_payload


def test_new_arrivals_older_occurrence_time_and_pagination(db, settings):
    dashboard = DashboardService(db, settings)
    assert dashboard.execute("updates", UpdatesQuery()).next_cursor == "0"
    ingest = EventIngestionService(db, settings)
    first = event_payload(timestamp="2026-10-01T12:00:00Z")
    assert ingest.ingest_batch([first]).summary.inserted == 1
    watermark = dashboard.execute("updates", UpdatesQuery())
    assert watermark.initialized and watermark.items == []
    older = event_payload(timestamp="2020-01-01T01:00:00Z")
    same = event_payload(timestamp="2026-10-01T12:00:00Z")
    third = event_payload(timestamp="2026-10-02T12:00:00Z")
    assert ingest.ingest_batch([older, same, third]).summary.inserted == 3
    after = int(watermark.next_cursor)
    page = dashboard.execute("updates", UpdatesQuery(after_id=after, limit=2))
    assert page.has_more and [p.event_id for p in page.items] == [
        older["event_id"],
        same["event_id"],
    ]
    rest = dashboard.execute("updates", UpdatesQuery(after_id=int(page.next_cursor), limit=2))
    assert not rest.has_more and [p.event_id for p in rest.items] == [third["event_id"]]
    empty = dashboard.execute("updates", UpdatesQuery(after_id=int(rest.next_cursor)))
    assert empty.items == [] and empty.next_cursor == rest.next_cursor
    replay = dashboard.execute("updates", UpdatesQuery(after_id=after, limit=2))
    assert [p.id for p in replay.items] == [p.id for p in page.items]
    assert len(dashboard.execute("updates", UpdatesQuery(after_id=0, limit=100)).items) == 4


def test_duplicate_and_rollback_gaps_are_safe(db, settings):
    ingest = EventIngestionService(db, settings)
    dashboard = DashboardService(db, settings)
    payload = event_payload()
    ingest.ingest_batch([payload])
    first = int(dashboard.execute("updates", UpdatesQuery()).next_cursor)
    ingest.ingest_batch([payload])
    assert int(dashboard.execute("updates", UpdatesQuery()).next_cursor) == first
    row = SecurityEvent(
        event_id="EVT-ROLLBACK",
        timestamp=datetime.now(UTC),
        source_ip="192.0.2.1",
        event_type="LOGIN_SUCCESS",
        status="success",
        raw_data={},
    )
    with db.begin_nested() as savepoint:
        db.add(row)
        db.flush()
        rolled_back = row.ingestion_sequence
        savepoint.rollback()
    fresh = event_payload()
    ingest.ingest_batch([fresh])
    page = dashboard.execute("updates", UpdatesQuery(after_id=first))
    assert [p.event_id for p in page.items] == [fresh["event_id"]]
    assert int(page.next_cursor) > rolled_back > first


def test_cursor_is_immutable_even_for_direct_sql(db, settings):
    EventIngestionService(db, settings).ingest_batch([event_payload()])
    before = db.scalar(select(SecurityEvent.ingestion_sequence))
    with pytest.raises(DBAPIError, match="immutable"), db.begin_nested():
        db.execute(text("UPDATE security_events SET ingestion_sequence=ingestion_sequence+100"))
    assert db.scalar(select(SecurityEvent.ingestion_sequence)) == before
    # Detection's processed update remains valid and never moves the polling position.
    db.execute(text("UPDATE security_events SET processed=true"))
    assert db.scalar(select(SecurityEvent.ingestion_sequence)) == before


def test_recent_watermark_is_usable_for_subsequent_api_poll(http, tokens, db, settings):
    now = datetime.now(UTC)
    ingest = EventIngestionService(db, settings)
    ingest.ingest_batch([event_payload(timestamp=now.isoformat())])
    response = http.get("/api/dashboard/events/recent", headers=tokens["VIEWER"])
    assert response.status_code == 200, response.text
    cursor = response.json()["polling_cursor"]
    assert isinstance(cursor, str) and response.json()["items"]
    late = event_payload(timestamp=(now - timedelta(days=100)).isoformat())
    ingest.ingest_batch([late])
    response = http.get(
        "/api/dashboard/events/updates", params={"after_id": cursor}, headers=tokens["VIEWER"]
    )
    assert (
        response.status_code == 200 and response.json()["items"][0]["event_id"] == late["event_id"]
    )


def test_recent_equal_timestamp_tie_breaks_by_uuid(db, settings):
    now = datetime.now(UTC) - timedelta(minutes=1)
    EventIngestionService(db, settings).ingest_batch(
        [event_payload(timestamp=now.isoformat()) for _ in range(4)]
    )
    expected = list(db.scalars(select(SecurityEvent.id).order_by(SecurityEvent.id.desc())))
    actual = DashboardService(db, settings).execute("recent_events", RecentQuery(limit=3))
    assert [p.id for p in actual.items] == expected[:3]


def test_migration_backfills_existing_data_without_rewriting_evidence(database_url):
    with isolated_schema(database_url) as engine:
        with engine.begin() as conn:
            config = migration_config(conn)
            command.upgrade(config, "0006_threat_intelligence")
            for index, created in enumerate(["2026-10-02T00:00:00Z", "2026-10-01T00:00:00Z"]):
                conn.execute(
                    text("""
                    INSERT INTO security_events
                        (id,event_id,timestamp,source_ip,event_type,status,raw_data,processed,created_at)
                    VALUES (:id,:event_id,'2020-01-01T00:00:00Z','192.0.2.1',
                            'LOGIN_SUCCESS','success',jsonb_build_object('original',true),false,:created)
                """),
                    {"id": uuid4(), "event_id": f"EVT-PRE10-{index}", "created": created},
                )
            before = dict(
                conn.execute(text("SELECT event_id,to_jsonb(e) FROM security_events e")).all()
            )
            command.upgrade(config, "head")
            command.check(config)
            rows = conn.execute(
                text(
                    "SELECT event_id,ingestion_sequence,to_jsonb(e)-'ingestion_sequence' "
                    "FROM security_events e ORDER BY ingestion_sequence"
                )
            ).all()
            assert [row[0] for row in rows] == ["EVT-PRE10-1", "EVT-PRE10-0"]
            assert [row[1] for row in rows] == [1, 2]
            assert {row[0]: row[2] for row in rows} == before
            conn.execute(
                text("""
                INSERT INTO security_events(event_id,timestamp,source_ip,event_type,status,raw_data)
                VALUES ('EVT-POST10','2019-01-01T00:00:00Z','192.0.2.2',
                        'LOGIN_SUCCESS','success','{}')
            """)
            )
            assert (
                conn.scalar(
                    text(
                        "SELECT ingestion_sequence FROM security_events WHERE event_id='EVT-POST10'"
                    )
                )
                == 3
            )
            command.downgrade(config, "0006_threat_intelligence")
            assert (
                dict(
                    conn.execute(
                        text(
                            "SELECT event_id,to_jsonb(e) FROM security_events e "
                            "WHERE event_id LIKE 'EVT-PRE10-%'"
                        )
                    ).all()
                )
                == before
            )


def test_native_concurrent_writer_cannot_commit_ahead_of_earlier_cursor(database_url, settings):
    """Runs on real multi-session PostgreSQL; embedded single-backend adapters cannot prove it."""
    with isolated_schema(database_url) as engine:
        with engine.begin() as conn:
            version = conn.scalar(text("SELECT version()"))
            if "Emscripten" in version or "emcc" in version:
                pytest.skip("Native PostgreSQL is required for independent writer concurrency")
            command.upgrade(migration_config(conn), "head")
        started = Event()
        values = dict(
            event_id="EVT-CONCURRENT-A",
            timestamp=datetime.now(UTC),
            source_ip="192.0.2.1",
            event_type="LOGIN_SUCCESS",
            status="success",
            raw_data={},
        )

        def later_writer():
            with engine.begin() as conn:
                conn.execute(text("SET LOCAL statement_timeout='3s'"))
                started.set()
                return conn.scalar(
                    SecurityEvent.__table__.insert()
                    .values(**dict(values, event_id="EVT-CONCURRENT-B"))
                    .returning(SecurityEvent.ingestion_sequence)
                )

        with engine.connect() as early, ThreadPoolExecutor(max_workers=1) as workers:
            tx = early.begin()
            try:
                seq = early.scalar(
                    SecurityEvent.__table__.insert()
                    .values(**values)
                    .returning(SecurityEvent.ingestion_sequence)
                )
                future = workers.submit(later_writer)
                assert started.wait(2)
                with pytest.raises(TimeoutError):
                    future.result(timeout=0.15)
                with Session(engine) as reader:
                    assert (
                        DashboardService(reader, settings)
                        .execute("updates", UpdatesQuery(after_id=0))
                        .items
                        == []
                    )
                tx.commit()
                assert future.result(timeout=3) > seq
                with Session(engine) as reader:
                    rows = (
                        DashboardService(reader, settings)
                        .execute("updates", UpdatesQuery(after_id=0))
                        .items
                    )
                    assert [p.event_id for p in rows] == ["EVT-CONCURRENT-A", "EVT-CONCURRENT-B"]
            finally:
                if tx.is_active:
                    tx.rollback()
