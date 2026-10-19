"""Explicit synthetic demo population through the existing authenticated HTTPS APIs.

Does not bypass the development-only guards on local DB utilities. No direct DB
access, role changes, provider keys, automatic retries or restart-time generation.
"""

import argparse
import json
import os
from datetime import UTC, date, datetime
from getpass import getpass
from itertools import batched
from pathlib import Path

import httpx

from app.simulation.config import SimulationConfig
from app.simulation.generator import SecurityEventGenerator
from scripts.verify_cloud import Checks, public_origin


def populate(client, *, start_date, count, resume=False):
    checks = Checks(client)
    if checks.request("Admin identity", "GET", "/api/auth/me").json()["role"] != "ADMIN":
        raise RuntimeError("Use a private administrator account for demo initialization")
    if (
        checks.request("Intelligence mode", "GET", "/api/threats/providers/status").json()["mode"]
        != "mock"
    ):
        raise RuntimeError("Demo initialization requires mock intelligence")
    if checks.request("Existing data", "GET", "/api/events?limit=1").json()["total"] and not resume:
        raise RuntimeError("Database already contains events; review before using --resume")
    rules = checks.request("Seeded rules", "GET", "/api/detection-rules").json()
    if len(rules) != 10 or not all(row["enabled"] for row in rules):
        raise RuntimeError("Seed and review all ten rules before demo initialization")
    result = {
        "seed": 42,
        "count": count,
        "start_date": str(start_date),
        "inserted": 0,
        "duplicates": 0,
    }
    generator = SecurityEventGenerator(
        SimulationConfig(
            count=count,
            seed=42,
            scenario="mixed",
            start_date=start_date,
        )
    )
    for batch in batched(generator.iter_events(), 500):
        response = checks.request(
            "Ingest batch",
            "POST",
            "/api/events/ingest/batch",
            json={"events": [event.model_dump(mode="json") for event in batch]},
        )
        summary = response.json()
        if not summary["complete"] or summary["failed"] or summary["invalid"]:
            raise RuntimeError("Ingestion incomplete; preserve the date and review before resuming")
        result["inserted"] += summary["inserted"]
        result["duplicates"] += summary["duplicates"]
    for name, path in (
        ("detection", "/api/detection/run"),
        ("risk", "/api/risk/run"),
        ("incidents", "/api/incidents/process"),
    ):
        summary = checks.request(name, "POST", path, json={"until_empty": True}).json()
        if not summary["complete"]:
            raise RuntimeError("Processing incomplete; inspect server logs before resuming")
        result[name] = {
            key: value for key, value in summary.items() if isinstance(value, (int, float, bool))
        }
    # Never trigger a paid provider: this runner requires the server to be in mock mode.
    offset = 0
    for _ in range(100):
        summary = checks.request(
            "Mock enrichment",
            "POST",
            "/api/threats/enrich/incidents",
            json={"limit": 50, "offset": offset},
        ).json()
        if not summary["complete"] or summary["external_lookups"] != 0:
            raise RuntimeError("Mock enrichment did not complete as expected")
        offset = summary["next_offset"]
        if offset is None:
            break
    else:
        raise RuntimeError("Enrichment exceeded the demo batch limit")
    remaining = checks.request(
        "Processing verification", "GET", "/api/events?processed=false&limit=1"
    ).json()["total"]
    if remaining:
        raise RuntimeError("Unprocessed events remain")
    result["unprocessed_events"] = remaining
    result["external_lookups"] = 0
    result["checks"] = checks.results
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", type=public_origin, required=True)
    parser.add_argument("--start-date", type=date.fromisoformat, required=True)
    parser.add_argument("--count", type=int, choices=[1000, 10000], default=10000)
    parser.add_argument("--confirm-synthetic-demo", action="store_true", required=True)
    parser.add_argument(
        "--resume",
        action="store_true",
        help="Only after reviewing an interrupted run; keep the original date/count",
    )
    parser.add_argument("--output", type=Path, default=Path("data/cloud-demo.json"))
    args = parser.parse_args(argv)
    result = {"status": "failed", "checked_at": datetime.now(UTC).isoformat()}
    username = os.environ.get("CLOUD_CHECK_USERNAME") or input("Private admin username: ")
    password = os.environ.get("CLOUD_CHECK_PASSWORD") or getpass("Password: ")
    try:
        with httpx.Client(
            base_url=args.url,
            timeout=110,
            follow_redirects=False,
            headers={"Origin": args.url, "X-CSRF-Guard": "1"},
        ) as client:
            login = client.post(
                "/api/auth/login", json={"username": username, "password": password}
            )
            login.raise_for_status()
            client.headers["Authorization"] = "Bearer " + login.json()["access_token"]
            try:
                result.update(
                    populate(
                        client, start_date=args.start_date, count=args.count, resume=args.resume
                    )
                )
                result["status"] = "passed"
            finally:
                client.post("/api/auth/logout")
    except Exception as exc:
        result["error_type"] = type(exc).__name__
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2), encoding="utf-8")
    print(f"Cloud demo: {result['status']}; report: {args.output}")
    return 0 if result["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
