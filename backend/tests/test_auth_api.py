"""Authentication and authorization against migrated PostgreSQL, not an in-memory ORM mock."""

import json
from datetime import UTC, datetime, timedelta
from unittest.mock import MagicMock
from uuid import UUID, uuid4

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError

from app.config import Settings
from app.core.enums import UserRole
from app.core.errors import ServiceError
from app.database import get_db
from app.main import create_app
from app.models import AuditLog, AuthSession, User
from app.schemas.auth import UserRegister
from app.security.jwt import create_access_token, create_refresh_token, decode_access_token
from app.security.passwords import hash_password, verify_password
from app.services.auth_service import token_digest
from app.services.user_service import bootstrap_admin

PASSWORD = "auth-test-only-passphrase"
GUARD = {"X-CSRF-Guard": "1"}


@pytest.fixture(scope="session")
def fixture_hash():
    return hash_password(PASSWORD)


@pytest.fixture
def users(db, fixture_hash):
    result = {}
    for role in UserRole:
        name = role.value.lower()
        user = User(
            username=name,
            email=f"{name}@cybersentinel.local",
            hashed_password=fixture_hash,
            role=role,
        )
        db.add(user)
        result[name] = user
    db.commit()
    return result


@pytest.fixture
def auth_http(db, monkeypatch):
    monkeypatch.setattr("app.main.build_engine", lambda settings: MagicMock())
    app = create_app(Settings(_env_file=None, app_env="test", auth_rate_limit_enabled=False))
    app.dependency_overrides[get_db] = lambda: db
    with TestClient(app) as client:
        yield client


def signin(http, username="viewer", password=PASSWORD):
    response = http.post(
        "/api/auth/login", json={"username": username, "password": password}, headers=GUARD
    )
    assert response.status_code == 200, response.text
    return response


def bearer(response):
    return {"Authorization": f"Bearer {response.json()['access_token']}"}


def registration(**changes):
    return {
        "username": "newviewer",
        "email": "newviewer@example.com",
        "password": PASSWORD,
        "full_name": "New Viewer",
        **changes,
    }


def test_registration_hashes_password_defaults_viewer_and_audits(auth_http, db):
    response = auth_http.post(
        "/api/auth/register",
        json=registration(username="NewViewer", email="NewViewer@Example.COM"),
        headers=GUARD,
    )
    assert response.status_code == 201
    data = response.json()
    assert data["username"] == "newviewer" and data["email"] == "newviewer@example.com"
    assert data["role"] == "VIEWER" and data["is_active"] is True
    user = db.get(User, UUID(data["id"]))
    assert user.hashed_password.startswith("$2b$")
    assert user.hashed_password != PASSWORD and verify_password(PASSWORD, user.hashed_password)
    assert not verify_password("wrong-passphrase", user.hashed_password)
    assert db.scalar(select(AuditLog.action)) == "USER_REGISTERED"
    assert "hashed_password" not in response.text and PASSWORD not in response.text


@pytest.mark.parametrize("change", [{"username": "ADMIN"}, {"email": "ADMIN@CyberSentinel.local"}])
def test_duplicate_identity_rejected(auth_http, users, change):
    response = auth_http.post("/api/auth/register", json=registration(**change), headers=GUARD)
    assert response.status_code == 409
    assert response.json()["detail"] == "Username or email is already in use"


@pytest.mark.parametrize(
    "change",
    [
        {"password": "weak-secret"},
        {"email": "invalid"},
        {"role": "ADMIN"},
        {"password": "é" * 40},
        {"is_active": True},
    ],
)
def test_bad_registration_is_clean_422(auth_http, change):
    response = auth_http.post("/api/auth/register", json=registration(**change), headers=GUARD)
    assert response.status_code == 422
    assert PASSWORD not in response.text and "weak-secret" not in response.text
    assert all("input" not in detail for detail in response.json()["detail"])
    assert auth_http.post("/api/auth/register", json={}, headers=GUARD).status_code == 422


def test_login_profile_cookie_and_openapi_never_expose_credentials(auth_http, users, db):
    response = signin(auth_http, " VIEWER ")
    assert response.json()["token_type"] == "bearer"
    assert 1798 <= response.json()["expires_in"] <= 1800
    assert "refresh_token" not in response.json()
    cookie = response.headers["set-cookie"]
    assert "HttpOnly" in cookie and "SameSite=strict" in cookie and "Path=/api/auth" in cookie
    me = auth_http.get("/api/auth/me", headers=bearer(response))
    assert me.status_code == 200 and me.json()["last_login"] is not None
    assert me.headers["cache-control"] == "no-store"
    for forbidden in (
        "hashed_password",
        PASSWORD,
        users["viewer"].hashed_password,
        auth_http.app.state.settings.jwt_secret_key.get_secret_value(),
        auth_http.app.state.settings.postgres_password.get_secret_value(),
    ):
        assert forbidden not in response.text + me.text
    sessions = db.scalars(select(AuthSession)).all()
    assert len(sessions) == 1
    assert sessions[0].refresh_token_hash == token_digest(auth_http.cookies.get("cs_refresh"))
    assert len(sessions[0].refresh_token_hash) == 64
    schema = auth_http.get("/openapi.json").json()
    assert schema["components"]["securitySchemes"]["BearerAuth"]["scheme"] == "bearer"
    assert schema["paths"]["/api/auth/me"]["get"]["security"] == [{"BearerAuth": []}]
    assert auth_http.get("/docs").status_code == 200


def test_failed_login_message_is_same_for_wrong_unknown_inactive(auth_http, users, db):
    users["analyst"].is_active = False
    db.commit()
    for name, password in [
        ("viewer", "wrong-passphrase"),
        ("unknown", PASSWORD),
        ("analyst", PASSWORD),
    ]:
        response = auth_http.post(
            "/api/auth/login", json={"username": name, "password": password}, headers=GUARD
        )
        assert response.status_code == 401
        assert response.json() == {"detail": "Invalid username or password"}
        assert response.headers["www-authenticate"] == "Bearer"
    assert list(db.scalars(select(AuditLog.action))) == ["LOGIN_FAILED"] * 3


@pytest.mark.parametrize(
    "path", ["/api/auth/me", "/api/users", "/api/test/authenticated", "/api/detection-rules"]
)
def test_protected_endpoints_require_valid_bearer(auth_http, path):
    for token in (None, "broken.token.value", "not-a-jwt"):
        response = auth_http.get(
            path, headers={"Authorization": f"Bearer {token}"} if token else {}
        )
        assert response.status_code == 401 and response.headers["www-authenticate"] == "Bearer"


@pytest.mark.parametrize(
    "role,expected",
    [("viewer", [200, 403, 403]), ("analyst", [200, 200, 403]), ("admin", [200, 200, 200])],
)
def test_role_matrix(auth_http, users, role, expected):
    headers = bearer(signin(auth_http, role))
    for route, code in zip(["authenticated", "analyst", "admin"], expected, strict=True):
        assert auth_http.get(f"/api/test/{route}", headers=headers).status_code == code
    assert auth_http.get("/api/users", headers=headers).status_code == expected[-1]


def test_database_role_is_authoritative(auth_http, users, db):
    headers = bearer(signin(auth_http, "viewer"))
    users["viewer"].role = UserRole.ANALYST
    db.commit()
    assert auth_http.get("/api/test/analyst", headers=headers).status_code == 200
    admin_headers = bearer(signin(auth_http, "admin"))
    users["admin"].role = UserRole.VIEWER
    db.commit()
    assert auth_http.get("/api/test/admin", headers=admin_headers).status_code == 403


@pytest.mark.parametrize("kind", ["expired", "refresh", "missing-user", "inactive"])
def test_expired_wrong_type_missing_or_inactive_user_rejected(auth_http, users, db, kind):
    response = signin(auth_http)
    settings = auth_http.app.state.settings
    claims = decode_access_token(response.json()["access_token"], settings)
    user = users["viewer"]
    if kind == "expired":
        token = create_access_token(
            user.id,
            UUID(claims["sid"]),
            user.role,
            settings,
            expires_at=datetime.now(UTC) - timedelta(seconds=1),
        )
    elif kind == "refresh":
        token = auth_http.cookies.get("cs_refresh")
    elif kind == "missing-user":
        token = create_access_token(uuid4(), UUID(claims["sid"]), user.role, settings)
    else:
        user.is_active = False
        db.commit()
        token = response.json()["access_token"]
    assert (
        auth_http.get("/api/auth/me", headers={"Authorization": f"Bearer {token}"}).status_code
        == 401
    )


def test_refresh_rotation_replay_revokes_entire_session(auth_http, users, db):
    signin(auth_http)
    original = auth_http.cookies.get("cs_refresh")
    expiry = db.scalar(select(AuthSession.expires_at))
    response = auth_http.post("/api/auth/refresh", json={}, headers=GUARD)
    assert response.status_code == 200
    rotated = auth_http.cookies.get("cs_refresh")
    assert original != rotated
    assert db.scalar(select(AuthSession.expires_at)) == expiry  # absolute lifetime
    assert auth_http.get("/api/auth/me", headers=bearer(response)).status_code == 200
    auth_http.cookies.clear()
    auth_http.cookies.set("cs_refresh", original)
    replay = auth_http.post("/api/auth/refresh", headers=GUARD)
    assert replay.status_code == 401
    assert auth_http.get("/api/auth/me", headers=bearer(response)).status_code == 401
    auth_http.cookies.clear()
    auth_http.cookies.set("cs_refresh", rotated)
    assert auth_http.post("/api/auth/refresh", headers=GUARD).status_code == 401
    assert "REFRESH_REPLAY_REJECTED" in db.scalars(select(AuditLog.action)).all()


@pytest.mark.parametrize("kind", ["expired", "access", "missing"])
def test_invalid_refresh_rejected(auth_http, users, kind):
    response = signin(auth_http)
    claims = decode_access_token(response.json()["access_token"], auth_http.app.state.settings)
    token = response.json()["access_token"]
    if kind == "expired":
        token = create_refresh_token(
            users["viewer"].id,
            UUID(claims["sid"]),
            UserRole.VIEWER,
            auth_http.app.state.settings,
            expires_at=datetime.now(UTC) - timedelta(days=1),
        )
    auth_http.cookies.clear()
    if kind != "missing":
        auth_http.cookies.set("cs_refresh", token)
    assert auth_http.post("/api/auth/refresh", json={}, headers=GUARD).status_code == 401


def test_logout_invalidates_access_and_refresh_and_clears_cookie(auth_http, users):
    login = signin(auth_http)
    original = auth_http.cookies.get("cs_refresh")
    response = auth_http.post("/api/auth/logout", headers={**GUARD, **bearer(login)})
    assert response.status_code == 204 and response.content == b""
    assert "Max-Age=0" in response.headers["set-cookie"]
    assert auth_http.cookies.get("cs_refresh") is None
    assert auth_http.get("/api/auth/me", headers=bearer(login)).status_code == 401
    auth_http.cookies.set("cs_refresh", original)
    assert auth_http.post("/api/auth/refresh", headers=GUARD).status_code == 401
    assert auth_http.post("/api/auth/logout", headers=GUARD).status_code == 204


def test_admin_lists_changes_and_audits_without_exposing_secrets(auth_http, users, db):
    headers = bearer(signin(auth_http, "admin"))
    listed = auth_http.get("/api/users?limit=1&offset=1", headers=headers)
    assert listed.status_code == 200 and listed.json()["total"] == 3
    assert len(listed.json()["items"]) == 1 and "hashed_password" not in listed.text
    user_id = users["viewer"].id
    assert auth_http.get(f"/api/users/{user_id}", headers=headers).status_code == 200
    assert auth_http.get(f"/api/users/{uuid4()}", headers=headers).status_code == 404
    response = auth_http.patch(
        f"/api/users/{user_id}/role", json={"role": "ANALYST"}, headers=headers
    )
    assert response.status_code == 200 and response.json()["role"] == "ANALYST"
    assert (
        auth_http.patch(
            f"/api/users/{user_id}/role", json={"role": "ROOT"}, headers=headers
        ).status_code
        == 422
    )
    assert (
        auth_http.patch(
            f"/api/users/{user_id}/status", json={"is_active": "false"}, headers=headers
        ).status_code
        == 422
    )
    audit = db.scalar(select(AuditLog).where(AuditLog.action == "USER_ROLE_CHANGED"))
    assert audit.old_value["role"] == "VIEWER" and audit.new_value["role"] == "ANALYST"
    assert audit.user_id == users["admin"].id
    audit_json = json.dumps(
        [{"old": row.old_value, "new": row.new_value} for row in db.scalars(select(AuditLog))]
    )
    assert PASSWORD not in audit_json and login_secret(headers) not in audit_json
    assert "hashed_password" not in audit_json


def login_secret(headers):
    return headers["Authorization"].removeprefix("Bearer ")


@pytest.mark.parametrize("role", ["viewer", "analyst"])
def test_non_admin_cannot_mutate_users(auth_http, users, role):
    headers = bearer(signin(auth_http, role))
    for action, payload in [("role", {"role": "ADMIN"}), ("status", {"is_active": False})]:
        assert (
            auth_http.patch(
                f"/api/users/{users['viewer'].id}/{action}", json=payload, headers=headers
            ).status_code
            == 403
        )


def test_last_active_admin_protection_and_second_admin(auth_http, users, db):
    headers = bearer(signin(auth_http, "admin"))
    admin_id = users["admin"].id
    # Inactive administrators cannot preserve access.
    users["analyst"].role = UserRole.ADMIN
    users["analyst"].is_active = False
    db.commit()
    for action, payload in [("role", {"role": "VIEWER"}), ("status", {"is_active": False})]:
        response = auth_http.patch(f"/api/users/{admin_id}/{action}", json=payload, headers=headers)
        assert response.status_code == 409
    assert (
        auth_http.patch(
            f"/api/users/{users['viewer'].id}/role", json={"role": "ADMIN"}, headers=headers
        ).status_code
        == 200
    )
    assert (
        auth_http.patch(
            f"/api/users/{admin_id}/role", json={"role": "VIEWER"}, headers=headers
        ).status_code
        == 200
    )
    assert auth_http.get("/api/test/admin", headers=headers).status_code == 403


def test_deactivation_revokes_all_sessions_and_reactivation_does_not_revive(auth_http, users, db):
    viewer = signin(auth_http)
    viewer_refresh = auth_http.cookies.get("cs_refresh")
    another = signin(auth_http)
    admin_headers = bearer(signin(auth_http, "admin"))
    path = f"/api/users/{users['viewer'].id}/status"
    assert (
        auth_http.patch(path, json={"is_active": False}, headers=admin_headers).status_code == 200
    )
    assert auth_http.patch(path, json={"is_active": True}, headers=admin_headers).status_code == 200
    for response in (viewer, another):
        assert auth_http.get("/api/auth/me", headers=bearer(response)).status_code == 401
    auth_http.cookies.clear()
    auth_http.cookies.set("cs_refresh", viewer_refresh)
    assert auth_http.post("/api/auth/refresh", headers=GUARD).status_code == 401
    assert signin(auth_http).status_code == 200
    actions = db.scalars(select(AuditLog.action)).all()
    assert "USER_DEACTIVATED" in actions and "USER_ACTIVATED" in actions


def test_csrf_and_cors_guards(auth_http, users):
    payload = {"username": "viewer", "password": PASSWORD}
    for headers in (
        {},
        {**GUARD, "Origin": "https://untrusted.example"},
        {**GUARD, "Sec-Fetch-Site": "cross-site"},
    ):
        assert auth_http.post("/api/auth/login", json=payload, headers=headers).status_code == 403
    response = auth_http.post(
        "/api/auth/login", json=payload, headers={**GUARD, "Origin": "http://localhost:5173"}
    )
    assert response.status_code == 200
    assert response.headers["access-control-allow-origin"] == "http://localhost:5173"
    assert response.headers["access-control-allow-credentials"] == "true"
    assert auth_http.post("/api/auth/logout").status_code == 403
    assert auth_http.post("/api/auth/refresh").status_code == 403


def test_production_refresh_cookie_is_secure(auth_http, users):
    auth_http.app.state.settings.app_env = "production"
    response = signin(auth_http)
    assert "; Secure" in response.headers["set-cookie"]


def test_recoverable_login_audit_failure_does_not_fail_login(auth_http, users, monkeypatch):
    def fail_audit(*args, **kwargs):
        raise SQLAlchemyError("audit fixture failure containing sensitive data")

    monkeypatch.setattr("app.services.audit_service.record_audit", fail_audit)
    response = signin(auth_http)
    assert auth_http.get("/api/auth/me", headers=bearer(response)).status_code == 200
    assert "sensitive data" not in response.text


def test_auth_rate_limits_return_retry_after(auth_http, users):
    settings = auth_http.app.state.settings
    settings.auth_rate_limit_enabled = True
    settings.auth_login_limit = 1
    signin(auth_http)
    response = auth_http.post(
        "/api/auth/login", json={"username": "viewer", "password": PASSWORD}, headers=GUARD
    )
    assert response.status_code == 429 and 1 <= int(response.headers["retry-after"]) <= 60


def test_real_failed_audit_insert_rolls_back_only_its_savepoint(auth_http, users, db, monkeypatch):
    from app.services.audit_service import record_audit

    def invalid_insert(session, action, **kwargs):
        kwargs["ip_address"] = "invalid-ip-fixture"
        record_audit(session, action, **kwargs)

    monkeypatch.setattr("app.services.audit_service.record_audit", invalid_insert)
    response = signin(auth_http)
    assert auth_http.get("/api/auth/me", headers=bearer(response)).status_code == 200
    assert db.scalar(select(AuthSession.id)) is not None
    assert db.scalar(select(AuditLog.id)) is None


def test_bootstrap_admin_is_idempotent_and_never_promotes_existing_viewer(db, users):
    payload = UserRegister(**registration(username="bootstrap", email="bootstrap@example.com"))
    first, created = bootstrap_admin(db, payload)
    assert created and first.role == UserRole.ADMIN
    initial_hash = first.hashed_password
    second, created = bootstrap_admin(db, payload.model_copy(update={"full_name": "No reset"}))
    assert not created and first.id == second.id and second.hashed_password == initial_hash
    with pytest.raises(ServiceError, match="conflicts"):
        bootstrap_admin(
            db, UserRegister(**registration(username="viewer", email="viewer@cybersentinel.local"))
        )
    assert users["viewer"].role == UserRole.VIEWER
