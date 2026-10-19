import hashlib
import json
import os
import subprocess
import sys
from datetime import datetime
from pathlib import Path

import pytest

from app.simulation.config import SimulationConfig
from app.simulation.exporter import export_events, validate_event
from app.simulation.generator import SecurityEventGenerator

BACKEND = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize("output_format", ["json", "jsonl"])
def test_formats_parse_and_match_generator(tmp_path, output_format):
    generator = SecurityEventGenerator(SimulationConfig())
    target = tmp_path / f"events.{output_format}"
    summary = export_events(generator, target, output_format)
    data = (
        json.loads(target.read_text())
        if output_format == "json"
        else [json.loads(line) for line in target.read_text().splitlines()]
    )
    assert data == [e.model_dump(mode="json") for e in generator.iter_events()]
    assert summary.total == 1000 and summary.normal == 950
    assert summary.sensitive_records["excessive_access"] == 500
    assert summary.first_timestamp < summary.last_timestamp
    assert "abnormal_api" in summary.render(generator, target, output_format)


def test_repeat_exports_are_byte_identical(tmp_path):
    paths = [tmp_path / "first.jsonl", tmp_path / "second.jsonl"]
    for path in paths:
        export_events(SecurityEventGenerator(), path)
    assert (
        hashlib.sha256(paths[0].read_bytes()).digest()
        == hashlib.sha256(paths[1].read_bytes()).digest()
    )


def test_json_and_jsonl_contain_identical_events(tmp_path):
    generator = SecurityEventGenerator(SimulationConfig(count=200))
    export_events(generator, tmp_path / "events.json", "json")
    export_events(generator, tmp_path / "events.jsonl")
    assert json.loads((tmp_path / "events.json").read_text()) == [
        json.loads(line) for line in (tmp_path / "events.jsonl").read_text().splitlines()
    ]


def test_overwrite_requires_explicit_flag(tmp_path):
    target = tmp_path / "events.jsonl"
    target.write_text("original")
    with pytest.raises(ValueError, match="already exists"):
        export_events(SecurityEventGenerator(), target)
    assert target.read_text() == "original"
    summary = export_events(SecurityEventGenerator(), target, overwrite=True)
    assert summary.total == 1000


def test_export_failure_preserves_existing_file_and_removes_temp(tmp_path, monkeypatch):
    generator = SecurityEventGenerator()
    one = next(generator.iter_records())

    def broken_stream():
        yield one
        raise ValueError("deliberate invalid record")

    monkeypatch.setattr(generator, "iter_records", broken_stream)
    target = tmp_path / "events.jsonl"
    target.write_text("original")
    with pytest.raises(ValueError, match="deliberate"):
        export_events(generator, target, overwrite=True)
    assert target.read_text() == "original"
    assert list(tmp_path.iterdir()) == [target]


@pytest.mark.parametrize(
    "field,value",
    [
        ("event_type", "UNKNOWN"),
        ("source_ip", "8.8.8.8"),
        ("destination_ip", "127.0.0.1"),
        ("source_port", 65536),
        ("timestamp", datetime(2026, 9, 26, 12)),
        ("event_id", "EVT-broken"),
    ],
)
def test_validation_rejects_corrupted_events(field, value):
    event = next(SecurityEventGenerator().iter_events())
    setattr(event, field, value)
    with pytest.raises(ValueError):
        validate_event(event)


def test_format_filename_mismatch_is_rejected(tmp_path):
    with pytest.raises(ValueError, match="filename"):
        export_events(SecurityEventGenerator(), tmp_path / "events.json", "jsonl")
    assert not list(tmp_path.iterdir())


@pytest.mark.parametrize(
    "entrypoint", [["scripts/generate_demo_data.py"], ["-m", "scripts.generate_demo_data"]]
)
def test_cli_works_without_settings_secrets_database_or_network(tmp_path, entrypoint):
    # A fresh interpreter rejects network, app.settings, and ORM imports during generation.
    guard = tmp_path / "sitecustomize.py"
    guard.write_text(
        "import sys\n"
        "def guard(event, args):\n"
        "    if event in {'socket.connect', 'socket.getaddrinfo'}:\n"
        "        raise RuntimeError('generator attempted a network operation')\n"
        "    if event == 'import' and args[0] in {'app.config', 'app.database', 'sqlalchemy'}:\n"
        "        raise RuntimeError('generator imported server/database settings')\n"
        "sys.addaudithook(guard)\n",
        encoding="utf-8",
    )
    env = {
        k: v
        for k, v in os.environ.items()
        if not k.startswith(("POSTGRES_", "JWT_", "DATABASE_", "TEST_DATABASE_"))
    }
    env["PYTHONPATH"] = str(tmp_path)
    target = tmp_path / "cli.jsonl"
    result = subprocess.run(
        [
            sys.executable,
            *entrypoint,
            "--count",
            "1000",
            "--seed",
            "42",
            "--scenario",
            "mixed",
            "--output",
            str(target),
        ],
        cwd=BACKEND,
        env=env,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, result.stderr
    assert len(target.read_text().splitlines()) == 1000
    assert "Normal events: 950" in result.stdout
    assert "Suspicious scenario events: 50" in result.stdout


@pytest.mark.parametrize(
    "arguments",
    [
        ["--count", "0"],
        ["--days", "0"],
        ["--normal-ratio", "NaN"],
        ["--scenario", "impossible_travel", "--count", "3"],
        ["--count", "10", "--preset", "small"],
    ],
)
def test_cli_invalid_input_has_actionable_error_without_output(tmp_path, arguments):
    target = tmp_path / "events.jsonl"
    result = subprocess.run(
        [sys.executable, "scripts/generate_demo_data.py", *arguments, "--output", str(target)],
        cwd=BACKEND,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 2 and "error:" in result.stderr
    assert not target.exists()
