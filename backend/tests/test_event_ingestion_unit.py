import json
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

import pytest

from app.config import Settings
from app.schemas.event_ingestion import EventQuery
from app.services.event_files import FileInputError, read_records
from app.services.event_normalizer import InvalidEvent, normalize_event


def event_payload(**changes):
    return {
        "event_id": f"EVT-{uuid4()}",
        "timestamp": "2026-09-26T10:00:00Z",
        "source_ip": "192.0.2.44",
        "destination_ip": "10.0.10.15",
        "username": "employee001",
        "event_type": "LOGIN_FAILED",
        "service": "authentication",
        "source_port": 55000,
        "destination_port": 443,
        "status": "failed",
        "raw_data": {"simulation": {"scenario": "brute_force", "scenario_id": "SIM-1"}},
        **changes,
    }


def test_normalization_preserves_raw_and_case_sensitive_identity():
    raw = {"simulation": {"scenario": "brute_force"}, "original": "  Do Not Change  "}
    original = event_payload(
        event_id=" EVT-CaseSensitive ",
        event_type=" login_failed ",
        status=" FAILED ",
        username=" UserCase ",
        service=" AuthService ",
        source_ip=" 2001:0db8:0000:0000:0000:0000:0000:0001 ",
        timestamp="2026-09-26T15:30:00+05:30",
        raw_data=raw,
    )
    event = normalize_event(original, 262144)
    assert event.event_id == "EVT-CaseSensitive" and event.event_type == "LOGIN_FAILED"
    assert (
        event.status == "failed" and event.username == "UserCase" and event.service == "AuthService"
    )
    assert str(event.source_ip) == "2001:db8::1"
    assert event.timestamp == datetime(2026, 9, 26, 10, tzinfo=UTC)
    assert event.raw_data == raw and original["event_type"] == " login_failed "


@pytest.mark.parametrize(
    "changes",
    [
        {"timestamp": "nonsense"},
        {"timestamp": "2026-09-26T10:00:00"},
        {"timestamp": "1000"},
        {"timestamp": 1000},
        {"source_ip": "999.1.1.1"},
        {"source_ip": "10.0.0.1/24"},
        {"source_ip": 1},
        {"destination_ip": "fe80::1%eth0"},
        {"source_port": -1},
        {"destination_port": 65536},
        {"source_port": True},
        {"username": 45},
        {"event_id": "  "},
        {"event_id": "EVT-/bad"},
        {"event_id": "x" * 129},
        {"event_type": "failed login"},
        {"status": "  "},
        {"raw_data": []},
        {"raw_data": {"bad": float("nan")}},
        {"raw_data": {"secret": "\x00"}},
        {"raw_data": {"secret": "\ud800"}},
        {"username": "\x00"},
        {"raw_data": {"unsupported": Path("example")}},
        {"processed": True},
        {"id": str(uuid4())},
        {"created_at": "2026-09-26T10:00:00Z"},
    ],
)
def test_invalid_events_rejected(changes):
    with pytest.raises(InvalidEvent):
        normalize_event(event_payload(**changes), 262144)


def test_event_size_and_deep_raw_data_rejected():
    with pytest.raises(InvalidEvent, match="byte limit"):
        normalize_event(event_payload(raw_data={"content": "x" * 3000}), 1024)
    raw = {}
    for _ in range(40):
        raw = {"level": raw}
    with pytest.raises(InvalidEvent, match="nesting"):
        normalize_event(event_payload(raw_data=raw), 262144)


def test_extensible_type_and_query_normalization():
    assert (
        normalize_event(event_payload(event_type=" vendor_signal "), 262144).event_type
        == "VENDOR_SIGNAL"
    )
    query = EventQuery(event_type=" login_failed ", status=" FAILED ", username=" UserCase ")
    assert (
        query.event_type == "LOGIN_FAILED"
        and query.status == "failed"
        and query.username == "UserCase"
    )


def test_jsonl_recovers_bad_lines_and_preserves_physical_positions(tmp_path):
    path = tmp_path / "events.jsonl"
    line = json.dumps(event_payload()).encode()
    path.write_bytes(
        b"\xef\xbb\xbf" + line + b"\n\n{bad json}\n" + b"x" * 3000 + b"\n\xff\n" + line + b"\n"
    )
    records = list(read_records(path, Settings(_env_file=None, ingestion_max_event_bytes=1024)))
    assert [r.line for r in records] == [1, 3, 4, 5, 6]
    assert [r.index for r in records] == [1, 2, 3, 4, 5]
    assert [r.code for r in records if r.error] == [
        "invalid_json",
        "record_too_large",
        "invalid_json",
    ]
    assert records[0].value == records[-1].value


@pytest.mark.parametrize(
    "content", [b"{bad}", b'"string"', b'{"a":1,"a":2}', b"[NaN]", b'["\xff"]']
)
def test_bad_json_file_rejected_before_writes(tmp_path, content):
    path = tmp_path / "events.json"
    path.write_bytes(content)
    with pytest.raises(FileInputError):
        list(read_records(path, Settings(_env_file=None)))


def test_json_array_single_object_and_size_limit(tmp_path):
    path = tmp_path / "events.json"
    data = event_payload()
    for value in (data, [data]):
        path.write_text(json.dumps(value))
        records = list(read_records(path, Settings(_env_file=None)))
        assert len(records) == 1 and records[0].value == data and records[0].line is None
    path.write_text(" " * 2048)
    with pytest.raises(FileInputError, match="streaming JSONL"):
        list(read_records(path, Settings(_env_file=None, ingestion_max_json_file_bytes=1024)))


@pytest.mark.parametrize(
    "body,status",
    [
        (b'{"event_id":"EVT-A","event_id":"EVT-B"}', 422),
        (b'{"raw_data":{"x":NaN}}', 422),
        (b"[" * 2000 + b"]" * 2000, 422),
        (b"\xff", 422),
    ],
)
def test_api_guard_rejects_ambiguous_or_malformed_json(body, status):
    import asyncio

    from app.security.ingestion_limits import IngestionBodyLimitMiddleware

    sent = []

    async def app(*args):
        pytest.fail("Invalid body must not reach a route")

    async def receive():
        return {"type": "http.request", "body": body, "more_body": False}

    async def send(message):
        sent.append(message)

    scope = {
        "type": "http",
        "method": "POST",
        "path": "/api/events/ingest",
        "headers": [(b"content-type", b"application/json")],
    }
    asyncio.run(IngestionBodyLimitMiddleware(app, 10000)(scope, receive, send))
    assert sent[0]["status"] == status


def test_api_size_limit_counts_chunked_bytes_not_content_length():
    import asyncio

    from app.security.ingestion_limits import IngestionBodyLimitMiddleware

    chunks = iter([b"x" * 600, b"y" * 600])
    sent = []

    async def app(*args):
        pytest.fail("Oversized body must not reach a route")

    async def receive():
        return {"type": "http.request", "body": next(chunks), "more_body": True}

    async def send(message):
        sent.append(message)

    scope = {
        "type": "http",
        "method": "POST",
        "path": "/api/events/ingest/batch",
        "headers": [(b"content-type", b"application/json"), (b"content-length", b"1")],
    }
    asyncio.run(IngestionBodyLimitMiddleware(app, 1024)(scope, receive, send))
    assert sent[0]["status"] == 413


@pytest.mark.parametrize(
    "entrypoint", [["scripts/ingest_events.py"], ["-m", "scripts.ingest_events"]]
)
def test_cli_entrypoints_document_options(entrypoint):
    import subprocess
    import sys

    result = subprocess.run(
        [sys.executable, *entrypoint, "--help"],
        cwd=Path(__file__).resolve().parents[1],
        capture_output=True,
        text=True,
        timeout=20,
    )
    assert result.returncode == 0
    assert "--batch-size" in result.stdout and "--rejected-output" in result.stdout
