"""Synchronous adapters match the existing SQLAlchemy/threadpool architecture."""

import json
from datetime import UTC, datetime, timedelta
from email.utils import parsedate_to_datetime
from time import monotonic, sleep
from typing import Protocol

import httpx

from app.threat_intelligence.schemas import ProviderResult
from app.threat_intelligence.utils.ip_validation import validate_ip
from app.threat_intelligence.utils.normalization import redact


class ThreatIntelligenceProvider(Protocol):
    name: str

    def is_configured(self) -> bool: ...
    def lookup_ip(self, ip: str) -> ProviderResult: ...


class HTTPProvider:
    name: str
    key_setting: str
    header: str
    enabled_setting: str
    # No caller or environment setting may change API hosts.
    host: str

    def __init__(self, settings, *, transport=None):
        self.settings = settings
        self.key = getattr(settings, self.key_setting).get_secret_value().strip()
        self.transport = transport
        self.requests = 0

    def is_configured(self):
        return bool(self.key)

    @property
    def enabled(self):
        return getattr(self.settings, self.enabled_setting)

    def result(self, ip, status, explanation, **values):
        now = datetime.now(UTC)
        ttl = (
            timedelta(hours=self.settings.threat_intelligence_cache_ttl_hours)
            if status == "success"
            else timedelta(seconds=self.settings.threat_intelligence_error_ttl_seconds)
        )
        retry = values.get("retry_at")
        return ProviderResult(
            provider=self.name,
            indicator=ip,
            lookup_status=status,
            explanation=explanation,
            checked_at=now,
            expires_at=max(now + ttl, retry) if retry else now + ttl,
            **values,
        )

    @property
    def interval_seconds(self):
        prefix = {"AbuseIPDB": "abuseipdb", "VirusTotal": "virustotal", "AlienVault OTX": "otx"}[
            self.name
        ]
        return getattr(self.settings, "threat_intelligence_" + prefix + "_interval_seconds")

    def lookup_ip(self, ip):
        result = self._lookup_once(ip)
        transient = result.lookup_status == "timeout" or (
            result.lookup_status == "provider_error" and result.http_status in {500, 502, 503, 504}
        )
        if (
            transient
            and result.retry_at is None
            and self.settings.threat_intelligence_max_retries
            and self.interval_seconds <= self.settings.threat_intelligence_max_retry_delay_seconds
        ):
            sleep(self.interval_seconds)
            result = self._lookup_once(ip)
        return result

    def _lookup_once(self, ip):
        target = validate_ip(ip)
        if not target.external_allowed:
            return self.result(target.ip, "not_applicable", target.reason)
        if not self.settings.threat_intelligence_enabled or not self.enabled:
            return self.result(target.ip, "disabled", "Provider disabled by configuration")
        if not self.is_configured():
            return self.result(target.ip, "not_configured", "Provider API key not configured")
        url, params = self.endpoint(target)
        if httpx.URL(url).scheme != "https" or httpx.URL(url).host != self.host:
            raise ValueError("Provider endpoint must use its fixed HTTPS host")
        deadline = monotonic() + self.settings.threat_intelligence_timeout_seconds
        try:
            with httpx.Client(
                timeout=self.settings.threat_intelligence_timeout_seconds,
                follow_redirects=False,
                trust_env=False,
                transport=self.transport,
                limits=httpx.Limits(max_connections=1, max_keepalive_connections=1),
                headers={self.header: self.key, "Accept": "application/json"},
            ) as client:
                self.requests += 1
                with client.stream("GET", url, params=params) as response:
                    status = response.status_code
                    if status != 200:
                        kind = (
                            "auth_error"
                            if status in {401, 403}
                            else "rate_limited"
                            if status == 429
                            else "not_found"
                            if status == 404
                            else "provider_error"
                        )
                        retry = retry_after(response.headers.get("Retry-After"))
                        return self.result(
                            target.ip,
                            kind,
                            {
                                "auth_error": "Provider credentials were rejected",
                                "rate_limited": "Provider request limit reached",
                                "not_found": "Provider has no available report",
                                "provider_error": "Provider request failed; reputation unknown",
                            }[kind],
                            http_status=status,
                            retry_at=retry,
                        )
                    body = bytearray()
                    for chunk in response.iter_bytes():
                        if monotonic() > deadline:
                            raise httpx.ReadTimeout("Request deadline")
                        body.extend(chunk)
                        if len(body) > self.settings.threat_intelligence_max_response_bytes:
                            return self.result(
                                target.ip,
                                "invalid_response",
                                "Provider response exceeds size limit",
                            )
                    payload = json.loads(
                        body, parse_constant=lambda x: (_ for _ in ()).throw(ValueError())
                    )
                    if not isinstance(payload, dict):
                        raise ValueError()
                    # JSON numbers such as 1e999 can become infinity without parse_constant.
                    json.dumps(payload, allow_nan=False)
                    secrets = [
                        getattr(self.settings, field).get_secret_value().strip()
                        for field in ("abuseipdb_api_key", "virustotal_api_key", "otx_api_key")
                    ]
                    # Error bodies/headers are never retained. Successful JSON is sanitized.
                    payload = redact(payload, secrets)
                    return self.normalize(target.ip, payload)
        except httpx.TimeoutException:
            return self.result(target.ip, "timeout", "Provider lookup timed out")
        except httpx.HTTPError:
            return self.result(target.ip, "provider_error", "Provider connection failed")
        except (ValueError, TypeError, KeyError, RecursionError):
            return self.result(
                target.ip, "invalid_response", "Provider returned an unsupported response"
            )


def retry_after(value):
    if value is None:
        return None
    now = datetime.now(UTC)
    try:
        if value.strip().isdigit():
            # Unreasonably large intervals fail closed at the datetime limit.
            return now + timedelta(
                seconds=min(
                    int(value), int((datetime.max.replace(tzinfo=UTC) - now).total_seconds()) - 1
                )
            )
        parsed = parsedate_to_datetime(value)
        if parsed.tzinfo is None:
            return None
        return max(now, parsed.astimezone(UTC))
    except (ValueError, OverflowError, TypeError):
        return None
