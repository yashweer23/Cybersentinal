"""Bounded HTTPS deployment checks. No data seeding, provider calls or load testing.

python -m scripts.verify_cloud --url https://ACTUAL-HOST --role VIEWER
Credentials are prompted without echo or supplied as CLOUD_CHECK_USERNAME/PASSWORD.
A role run creates/rotates/revokes its own login session; all other checks are read-only
or attempt forbidden changes to randomly generated, nonexistent resources.
"""

import argparse
import csv
import io
import json
import os
from datetime import UTC, datetime
from getpass import getpass
from pathlib import Path
from time import perf_counter
from urllib.parse import urlsplit
from uuid import uuid4

import httpx


def public_origin(value):
    parts = urlsplit(value)
    if (
        parts.scheme != "https"
        or not parts.hostname
        or parts.username
        or parts.password
        or parts.path
        or parts.query
        or parts.fragment
        or "*" in value
        or parts.port not in (None, 443)
    ):
        raise argparse.ArgumentTypeError(
            "Use the exact public HTTPS origin without a trailing slash"
        )
    return value


class Checks:
    def __init__(self, client):
        self.client = client
        self.results = []

    def request(self, label, method, path, expected=200, **kwargs):
        started = perf_counter()
        response = self.client.request(method, path, **kwargs)
        self.results.append(
            {
                "check": label,
                "status_code": response.status_code,
                "duration_ms": round((perf_counter() - started) * 1000, 3),
            }
        )
        if response.status_code != expected:
            raise RuntimeError(f"{label}: expected HTTP {expected}; got {response.status_code}")
        return response


def verify(client, origin, role=None, username=None, password=None):
    check = Checks(client)
    for route in ("/", "/incidents", "/analytics", "/ai-analyst", "/threat-intelligence"):
        page = check.request("SPA " + route, "GET", route)
        if "text/html" not in page.headers.get("content-type", "") or 'id="root"' not in page.text:
            raise RuntimeError("SPA fallback did not return the application shell")
    check.request("Frontend liveness", "GET", "/healthz")
    ready = check.request("API readiness", "GET", "/api/system/ready")
    if ready.json().get("status") != "ready" or not ready.headers.get("x-request-id"):
        raise RuntimeError("Readiness or request correlation failed")
    check.request("Swagger", "GET", "/docs")
    schema = check.request("OpenAPI", "GET", "/openapi.json").json()
    if "/api/auth/login" not in schema.get("paths", {}):
        raise RuntimeError("Expected API routes are missing")
    check.request("Protected dashboard", "GET", "/api/dashboard/overview", expected=401)
    cors = {
        "Origin": origin,
        "Access-Control-Request-Method": "POST",
        "Access-Control-Request-Headers": "content-type,x-csrf-guard",
    }
    accepted = check.request("Exact-origin CORS", "OPTIONS", "/api/auth/login", headers=cors)
    if accepted.headers.get("access-control-allow-origin") != origin:
        raise RuntimeError("Production CORS origin did not match")
    check.request(
        "Unrelated-origin CORS",
        "OPTIONS",
        "/api/auth/login",
        expected=400,
        headers={**cors, "Origin": "https://unrelated.invalid"},
    )
    if role:
        client.headers.update({"Origin": origin, "X-CSRF-Guard": "1"})
        logged_in = False
        try:
            login = check.request(
                "Login",
                "POST",
                "/api/auth/login",
                json={"username": username, "password": password},
            )
            logged_in = True
            payload = login.json()
            if payload["user"]["role"] != role:
                raise RuntimeError("Account role does not match requested check")
            cookie = login.headers.get("set-cookie", "").lower()
            if not all(part in cookie for part in ("secure", "httponly", "samesite=strict")):
                raise RuntimeError("Refresh cookie is missing production flags")
            client.headers["Authorization"] = "Bearer " + payload["access_token"]
            check.request("Current user", "GET", "/api/auth/me")
            refreshed = check.request("Refresh rotation", "POST", "/api/auth/refresh", json={})
            client.headers["Authorization"] = "Bearer " + refreshed.json()["access_token"]
            check.request("Dashboard", "GET", "/api/dashboard/overview")
            check.request("Analytics", "GET", "/api/analytics/overview")
            check.request("Detection rules", "GET", "/api/detection-rules")
            incidents = check.request("Incidents", "GET", "/api/incidents?limit=1").json()
            if incidents["items"]:
                incident_id = incidents["items"][0]["incident_id"]
                check.request("Incident investigation", "GET", f"/api/incidents/{incident_id}")
            check.request(
                "User administration RBAC",
                "GET",
                "/api/users?limit=1",
                expected=200 if role == "ADMIN" else 403,
            )
            if role != "ADMIN":
                check.request(
                    "Rule configuration RBAC",
                    "PATCH",
                    "/api/detection-rules/CS-999",
                    expected=403,
                    json={"enabled": True},
                )
            if role == "VIEWER":
                check.request(
                    "Incident mutation RBAC",
                    "PATCH",
                    f"/api/incidents/CLOUD-CHECK-{uuid4().hex}/status",
                    expected=403,
                    json={"status": "INVESTIGATING"},
                )
                check.request("Report export RBAC", "GET", "/api/reports/incidents", expected=403)
            else:
                report = check.request(
                    "CSV export", "GET", "/api/reports/incidents?format=csv&limit=5"
                )
                if "attachment" not in report.headers.get("content-disposition", ""):
                    raise RuntimeError("Report is not a downloadable attachment")
                if len(list(csv.reader(io.StringIO(report.text)))) < 1:
                    raise RuntimeError("CSV report is empty")
            check.request("Logout", "POST", "/api/auth/logout", expected=204)
            logged_in = False
            check.request("Revoked session", "GET", "/api/auth/me", expected=401)
        finally:
            if logged_in:
                client.post("/api/auth/logout")
            client.headers.pop("Authorization", None)
    return check.results


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", required=True, type=public_origin)
    parser.add_argument("--role", choices=["ADMIN", "ANALYST", "VIEWER"])
    parser.add_argument("--output", type=Path, default=Path("data/cloud-checks.json"))
    args = parser.parse_args(argv)
    username = password = None
    if args.role:
        username = os.environ.get("CLOUD_CHECK_USERNAME") or input("Username: ")
        password = os.environ.get("CLOUD_CHECK_PASSWORD") or getpass("Password: ")
    result = {
        "checked_at": datetime.now(UTC).isoformat(),
        "origin": args.url,
        "role": args.role,
        "status": "failed",
        "scope": "bounded HTTPS smoke checks",
    }
    try:
        with httpx.Client(base_url=args.url, timeout=30, follow_redirects=False) as client:
            redirect = client.get(args.url.replace("https://", "http://", 1) + "/healthz")
            if (
                redirect.status_code not in (301, 302, 307, 308)
                or redirect.headers.get("location") != args.url + "/healthz"
            ):
                raise RuntimeError("HTTP did not redirect to the same HTTPS origin")
            result["checks"] = verify(client, args.url, args.role, username, password)
        result["status"] = "passed"
    except Exception as exc:
        result["error_type"] = type(exc).__name__
        # Do not write response bodies, credentials, tokens or exception details.
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2), encoding="utf-8")
    print(f"Cloud checks: {result['status']}; report: {args.output}")
    return 0 if result["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
