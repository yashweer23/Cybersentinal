"""Validated configuration shared by the API and Alembic."""

from functools import lru_cache
from pathlib import Path
from typing import Literal

from pydantic import AliasChoices, Field, SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict
from sqlalchemy import URL
from sqlalchemy.engine import make_url

from app.risk.config import RiskScoringConfig

PROJECT_ROOT = Path(__file__).resolve().parents[2]


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=PROJECT_ROOT / ".env",
        env_file_encoding="utf-8-sig",
        case_sensitive=False,
        extra="ignore",
        hide_input_in_errors=True,
    )

    app_env: Literal["development", "test", "production"] = "development"
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"] = "INFO"
    api_docs_enabled: bool = True
    allowed_hosts: list[str] = ["localhost", "127.0.0.1", "backend"]
    server_host: str = "0.0.0.0"
    server_port: int = Field(
        default=8000,
        ge=1024,
        le=65535,
        validation_alias=AliasChoices("server_port", "PORT"),
    )
    # Canonical HTTPS origin behind the private cloud gateway; never read from a request.
    public_origin: str | None = None
    # Rate limits are process-local: scaling workers needs a deliberate shared-limit design.
    server_workers: Literal[1] = 1
    server_graceful_timeout_seconds: int = Field(default=60, ge=5, le=300)
    proxy_headers_enabled: bool = False
    forwarded_allow_ips: list[str] = ["127.0.0.1", "::1"]
    db_pool_size: int = Field(default=5, ge=1, le=20)
    db_max_overflow: int = Field(default=5, ge=0, le=20)
    db_pool_timeout_seconds: int = Field(default=3, ge=1, le=30)
    db_pool_recycle_seconds: int = Field(default=1800, ge=60, le=86400)
    db_connect_timeout_seconds: int = Field(default=3, ge=1, le=30)
    db_statement_timeout_ms: int = Field(default=3000, ge=1000, le=120000)
    dashboard_max_range_days: int = Field(default=90, ge=30, le=366)
    dashboard_slow_query_ms: int = Field(default=250, ge=1, le=10000)
    postgres_host: str = "127.0.0.1"
    postgres_port: int = Field(default=5432, ge=1, le=65535)
    postgres_db: str = Field(default="cybersentinel", min_length=1)
    postgres_user: str = Field(default="cybersentinel", min_length=1)
    postgres_password: SecretStr | None = None
    database_connection_url: SecretStr | None = Field(
        default=None, validation_alias=AliasChoices("DATABASE_URL", "database_connection_url")
    )
    database_sslmode: Literal["require", "verify-ca", "verify-full"] | None = None
    jwt_secret_key: SecretStr
    jwt_algorithm: Literal["HS256"] = "HS256"
    jwt_access_token_expire_minutes: int = Field(default=30, ge=1, le=120)
    jwt_refresh_token_expire_days: int = Field(default=7, ge=1, le=30)
    jwt_issuer: str = "cybersentinel"
    jwt_audience: str = "cybersentinel-api"
    backend_port: int = Field(default=8000, ge=1, le=65535)
    auth_trusted_origins: list[str] = []
    auth_rate_limit_enabled: bool = True
    auth_login_limit: int = Field(default=10, ge=1, le=1000)
    auth_register_limit: int = Field(default=5, ge=1, le=1000)
    auth_refresh_limit: int = Field(default=30, ge=1, le=1000)
    ai_analyst_enabled: bool = True
    ai_provider: Literal["", "fallback", "openai"] = ""
    ai_api_key: SecretStr = SecretStr("")
    ai_model: str = Field(default="", max_length=100, pattern=r"^[A-Za-z0-9._:-]*$")
    ai_request_timeout_seconds: float = Field(default=30, ge=1, le=60)
    ai_max_context_events: int = Field(default=50, ge=2, le=100)
    ai_max_context_findings: int = Field(default=20, ge=1, le=50)
    ai_max_response_tokens: int = Field(default=1500, ge=256, le=4000)
    ai_analysis_cache_enabled: bool = True
    ai_rate_limit_per_minute: int = Field(default=10, ge=1, le=60)
    ai_fallback_cache_seconds: int = Field(default=60, ge=0, le=600)
    abuseipdb_api_key: SecretStr = SecretStr("")
    virustotal_api_key: SecretStr = SecretStr("")
    otx_api_key: SecretStr = SecretStr("")
    abuseipdb_enabled: bool = True
    virustotal_enabled: bool = True
    otx_enabled: bool = True
    threat_intelligence_enabled: bool = True
    threat_intelligence_mock_mode: bool = True
    threat_intelligence_cache_ttl_hours: int = Field(default=24, ge=1, le=168)
    threat_intelligence_error_ttl_seconds: int = Field(default=300, ge=1, le=3600)
    threat_intelligence_timeout_seconds: float = Field(default=10, ge=0.1, le=30)
    threat_intelligence_max_retries: int = Field(default=1, ge=0, le=1)
    threat_intelligence_max_retry_delay_seconds: int = Field(default=2, ge=0, le=15)
    threat_intelligence_run_timeout_seconds: int = Field(default=60, ge=1, le=300)
    threat_intelligence_max_response_bytes: int = Field(default=524288, ge=1024, le=2097152)
    threat_intelligence_max_incidents: int = Field(default=50, ge=1, le=100)
    threat_intelligence_max_indicators: int = Field(default=100, ge=1, le=500)
    threat_intelligence_abuseipdb_interval_seconds: int = Field(default=1, ge=1, le=3600)
    threat_intelligence_virustotal_interval_seconds: int = Field(default=15, ge=1, le=3600)
    threat_intelligence_otx_interval_seconds: int = Field(default=1, ge=1, le=3600)
    risk_scoring: RiskScoringConfig = Field(default_factory=RiskScoringConfig)
    incident_min_risk_score: int = Field(default=50, ge=0, le=100)
    incident_correlation_window_minutes: int = Field(default=60, ge=1, le=1440)
    incident_correlation_min_score: int = Field(default=8, ge=8, le=12)
    incident_reopen_window_minutes: int = Field(default=0, ge=0, le=1440)
    incident_batch_size: int = Field(default=100, ge=1, le=500)
    incident_max_batches: int = Field(default=100, ge=1, le=1000)
    incident_max_candidates: int = Field(default=1000, ge=1, le=10000)
    risk_batch_size: int = Field(default=250, ge=1, le=500)
    risk_max_batches: int = Field(default=100, ge=1, le=1000)
    risk_max_context_events: int = Field(default=10000, ge=100, le=50000)
    detection_batch_size: int = Field(default=500, ge=1, le=1000)
    detection_max_batches: int = Field(default=100, ge=1, le=1000)
    detection_max_context_events: int = Field(default=50000, ge=1000, le=200000)
    detection_evidence_limit: int = Field(default=100, ge=2, le=200)
    ingestion_max_batch_size: int = Field(default=1000, ge=1, le=1000)
    ingestion_max_errors: int = Field(default=20, ge=1, le=100)
    ingestion_max_event_bytes: int = Field(default=262144, ge=1024, le=1048576)
    ingestion_max_request_bytes: int = Field(default=8388608, ge=1024, le=33554432)
    ingestion_max_json_file_bytes: int = Field(default=16777216, ge=1024, le=67108864)
    cors_origins: list[str] = ["http://localhost:5173", "http://127.0.0.1:5173"]

    @field_validator("postgres_password")
    @classmethod
    def validate_password(cls, value: SecretStr | None) -> SecretStr | None:
        if value is None:
            return value
        password = value.get_secret_value()
        if len(password) < 16 or password.startswith("CHANGE_ME"):
            raise ValueError("Generate a database password with Initialize-Environment.ps1")
        return value

    @field_validator("jwt_secret_key")
    @classmethod
    def validate_jwt_secret(cls, value: SecretStr) -> SecretStr:
        secret = value.get_secret_value()
        if len(secret.encode("utf-8")) < 32 or secret.startswith(("CHANGE_ME", "replace-with")):
            raise ValueError(
                "JWT_SECRET_KEY must be a locally generated random secret of 32+ bytes"
            )
        return value

    @field_validator("cors_origins", "auth_trusted_origins")
    @classmethod
    def validate_origins(cls, origins: list[str]) -> list[str]:
        from urllib.parse import urlsplit

        for origin in origins:
            parsed = urlsplit(origin)
            if (
                parsed.scheme not in {"http", "https"}
                or not parsed.netloc
                or parsed.path
                or parsed.query
                or parsed.fragment
                or parsed.username
                or parsed.password
                or "*" in origin
            ):
                raise ValueError("CORS_ORIGINS must contain explicit HTTP origins without paths")
        return origins

    @field_validator("allowed_hosts")
    @classmethod
    def validate_hosts(cls, values: list[str]) -> list[str]:
        import re

        if not values or any(
            not re.fullmatch(r"(?:\*\.)?[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?", host)
            or ".." in host
            for host in values
        ):
            raise ValueError("ALLOWED_HOSTS requires explicit hosts, without schemes or ports")
        return values

    @field_validator("forwarded_allow_ips")
    @classmethod
    def validate_proxy_networks(cls, values: list[str]) -> list[str]:
        from ipaddress import ip_network

        for value in values:
            try:
                network = ip_network(value, strict=False)
            except ValueError:
                raise ValueError(
                    "FORWARDED_ALLOW_IPS requires explicit IPs/CIDRs; no wildcard"
                ) from None
            if network.prefixlen == 0:
                raise ValueError("Trust a restricted proxy network, not every address")
        return values

    @field_validator("server_host")
    @classmethod
    def validate_server_host(cls, value: str) -> str:
        from ipaddress import ip_address

        return str(ip_address(value))

    @field_validator("public_origin")
    @classmethod
    def validate_public_origin(cls, value: str | None) -> str | None:
        from urllib.parse import urlsplit

        if value is None:
            return None
        cls.validate_origins([value])
        parsed = urlsplit(value)
        if parsed.scheme != "https" or parsed.port not in (None, 443):
            raise ValueError("PUBLIC_ORIGIN requires an exact HTTPS origin on port 443")
        cls.validate_hosts([parsed.hostname or ""])
        return value

    @field_validator("database_connection_url")
    @classmethod
    def validate_database_connection_url(cls, value: SecretStr | None) -> SecretStr | None:
        if value is None:
            return None
        try:
            url = make_url(value.get_secret_value())
            if (
                url.drivername not in {"postgres", "postgresql", "postgresql+psycopg"}
                or not all((url.username, url.password, url.host, url.database))
                or (url.port is not None and not 1 <= url.port <= 65535)
                or set(url.query) - {"sslmode", "sslrootcert", "channel_binding"}
                or any(not isinstance(v, str) for v in url.query.values())
            ):
                raise ValueError
            if url.query.get("sslmode", "require") not in {"require", "verify-ca", "verify-full"}:
                raise ValueError
        except Exception:
            # Parser exceptions may contain the complete credential-bearing URL.
            raise ValueError(
                "DATABASE_URL requires PostgreSQL credentials, host, database and TLS options"
            ) from None
        return value

    @model_validator(mode="after")
    def production_configuration(self):
        if self.database_connection_url is None and self.postgres_password is None:
            raise ValueError("Set DATABASE_URL or POSTGRES_PASSWORD")
        if self.public_origin:
            from urllib.parse import urlsplit

            # Same-origin cloud deployment has one explicit browser origin.
            self.cors_origins = [self.public_origin]
            self.auth_trusted_origins = [self.public_origin]
            host = urlsplit(self.public_origin).hostname
            self.allowed_hosts = list(dict.fromkeys([*self.allowed_hosts, host]))
            if self.proxy_headers_enabled:
                raise ValueError("PUBLIC_ORIGIN mode must not also trust forwarded headers")
        if self.app_env == "production":
            if self.log_level == "DEBUG":
                raise ValueError("Production LOG_LEVEL must be INFO or higher")
            for secret in (self.jwt_secret_key.get_secret_value(), self.database_url.password):
                value = secret.lower()
                if (
                    len(secret) < 16
                    or len(set(value)) < 8
                    or any(
                        marker in value
                        for marker in (
                            "changeme",
                            "change_me",
                            "development-secret",
                            "replace-with",
                            "password123",
                        )
                    )
                ):
                    raise ValueError("Production requires generated database and JWT secrets")
        return self

    @property
    def cookie_secure(self) -> bool:
        return self.app_env == "production"

    @property
    def trusted_browser_origins(self) -> set[str]:
        origins = set(self.cors_origins) | set(self.auth_trusted_origins)
        if self.app_env != "production":
            origins.update(
                {f"http://localhost:{self.backend_port}", f"http://127.0.0.1:{self.backend_port}"}
            )
        return origins

    @property
    def database_url(self) -> URL:
        if self.database_connection_url is not None:
            url = make_url(self.database_connection_url.get_secret_value()).set(
                drivername="postgresql+psycopg"
            )
            # Provider URLs take precedence over local POSTGRES_* settings. A URL never
            # silently falls back to plaintext, including when PGSSLMODE is inherited.
            tls_mode = self.database_sslmode or url.query.get("sslmode", "require")
            strengths = {"require": 1, "verify-ca": 2, "verify-full": 3}
            if strengths[tls_mode] < strengths.get(url.query.get("sslmode"), 0):
                raise ValueError("DATABASE_SSLMODE must not weaken DATABASE_URL TLS validation")
            return url.update_query_dict({"sslmode": tls_mode})
        # URL.create preserves special characters in passwords without manual escaping.
        return URL.create(
            "postgresql+psycopg",
            username=self.postgres_user,
            password=self.postgres_password.get_secret_value(),
            host=self.postgres_host,
            port=self.postgres_port,
            database=self.postgres_db,
        )


@lru_cache
def get_settings() -> Settings:
    return Settings()
