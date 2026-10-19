from datetime import UTC, datetime, timedelta
from email.utils import format_datetime

import httpx
import pytest
from pydantic import SecretStr

from app.config import Settings
from app.detection.reputation import LocalSyntheticReputationProvider
from app.threat_intelligence.aggregator import aggregate
from app.threat_intelligence.providers.abuseipdb import AbuseIPDBProvider
from app.threat_intelligence.providers.base import retry_after
from app.threat_intelligence.providers.mock_provider import MockProvider
from app.threat_intelligence.providers.otx import OTXProvider
from app.threat_intelligence.providers.virustotal import VirusTotalProvider
from app.threat_intelligence.utils.ip_validation import validate_ip

IP = "8.8.8.8"
KEY = "unit-fixture-provider-key-never-live"


def config(**kwargs):
    return Settings(
        _env_file=None,
        abuseipdb_api_key=KEY,
        virustotal_api_key=KEY,
        otx_api_key=KEY,
        threat_intelligence_max_retries=0,
        **kwargs,
    )


def abuse(ip=IP, score=90):
    return {
        "data": {
            "ipAddress": ip,
            "abuseConfidenceScore": score,
            "totalReports": 12,
            "countryCode": "US",
            "isp": "Fixture ISP",
            "usageType": "Test",
            "lastReportedAt": "2026-10-01T12:00:00Z",
        }
    }


def vt(ip=IP, malicious=3, suspicious=1, undetected=10):
    return {
        "data": {
            "id": ip,
            "type": "ip_address",
            "attributes": {
                "last_analysis_stats": {
                    "malicious": malicious,
                    "suspicious": suspicious,
                    "harmless": 0,
                    "undetected": undetected,
                },
                "reputation": -12,
                "last_analysis_date": 1790856000,
                "tags": ["untrusted-tag"],
            },
        }
    }


def otx(ip=IP, count=2):
    return {
        "indicator": ip,
        "pulse_info": {
            "count": count,
            "pulses": [
                {"id": "fixture-pulse", "tags": ["test-context"], "created": "2026-10-01T00:00:00Z"}
            ],
        },
    }


@pytest.mark.parametrize("ip", [IP, "1.1.1.1", "2606:4700:4700::1111"])
def test_public_ip_allowed(ip):
    assert validate_ip(ip).external_allowed


@pytest.mark.parametrize(
    "ip",
    [
        "192.168.1.1",
        "10.0.0.1",
        "127.0.0.1",
        "169.254.1.1",
        "224.0.0.1",
        "0.0.0.0",
        "100.64.0.1",
        "198.18.0.1",
        "192.0.2.44",
        "198.51.100.73",
        "203.0.113.18",
        "::",
        "::1",
        "fe80::1",
        "fc00::1",
        "ff02::1",
        "2001:db8::1",
        "3fff::1",
        "::ffff:8.8.8.8",
        "64:ff9b::808:808",
        "2002:808:808::1",
    ],
)
def test_ineligible_never_reaches_network(ip):
    assert not validate_ip(ip).external_allowed

    def forbidden(request):
        pytest.fail("Indicator unexpectedly sent to provider")

    for cls in (AbuseIPDBProvider, VirusTotalProvider, OTXProvider):
        provider = cls(config(), transport=httpx.MockTransport(forbidden))
        assert provider.lookup_ip(ip).lookup_status == "not_applicable"
        assert provider.requests == 0


@pytest.mark.parametrize(
    "ip", ["example.com", "http://8.8.8.8", "8.8.8.8/32", "bad", "1.2.3.999", "fe80::1%eth0", ""]
)
def test_invalid_ip_rejected(ip):
    with pytest.raises(ValueError):
        validate_ip(ip)


@pytest.mark.parametrize(
    "cls,body,host,header,score",
    [
        (AbuseIPDBProvider, abuse(), "api.abuseipdb.com", "Key", 90),
        (VirusTotalProvider, vt(), "www.virustotal.com", "x-apikey", 75),
        (OTXProvider, otx(), "otx.alienvault.com", "X-OTX-API-KEY", 35),
    ],
)
def test_official_request_shapes_normalization_and_raw_preservation(cls, body, host, header, score):
    def handler(request):
        assert request.method == "GET" and request.url.host == host
        assert request.url.scheme == "https" and request.headers[header] == KEY
        assert KEY not in str(request.url) and request.content == b""
        if cls == AbuseIPDBProvider:
            assert request.url.path == "/api/v2/check"
            assert request.url.params["ipAddress"] == IP
            assert request.url.params["maxAgeInDays"] == "90"
        elif cls == VirusTotalProvider:
            assert request.url.path == "/api/v3/ip_addresses/" + IP
        else:
            assert request.url.path == "/api/v1/indicators/IPv4/" + IP + "/general"
        return httpx.Response(200, json=body)

    provider = cls(config(), transport=httpx.MockTransport(handler))
    result = provider.lookup_ip(IP)
    assert result.lookup_status == "success" and result.normalized_score == score
    assert result.raw_response == body and not result.simulation
    assert result.expires_at - result.checked_at == timedelta(hours=24)


@pytest.mark.parametrize(
    "cls,body", [(AbuseIPDBProvider, abuse), (VirusTotalProvider, vt), (OTXProvider, otx)]
)
def test_ipv6_endpoint_and_canonical_identity(cls, body):
    ip = "2606:4700:4700::1111"
    seen = []

    def handler(request):
        seen.append(str(request.url))
        return httpx.Response(200, json=body(ip))

    result = cls(config(), transport=httpx.MockTransport(handler)).lookup_ip(ip)
    assert result.indicator == ip and result.lookup_status == "success"
    assert len(seen) == 1


@pytest.mark.parametrize(
    "status,expected",
    [
        (401, "auth_error"),
        (403, "auth_error"),
        (429, "rate_limited"),
        (500, "provider_error"),
        (503, "provider_error"),
        (404, "not_found"),
        (302, "provider_error"),
    ],
)
def test_provider_errors_are_unknown_and_do_not_expose_bodies(status, expected):
    provider = AbuseIPDBProvider(
        config(),
        transport=httpx.MockTransport(
            lambda r: httpx.Response(
                status, json={"error": KEY}, headers={"Location": "http://127.0.0.1"}
            )
        ),
    )
    result = provider.lookup_ip(IP)
    assert result.lookup_status == expected and result.reputation_level == "UNKNOWN"
    assert result.normalized_score is None and result.malicious is None
    assert KEY not in result.model_dump_json() and result.raw_response == {}
    assert provider.requests == 1


def test_timeout_missing_key_and_disabled():
    def timeout(r):
        raise httpx.ReadTimeout("sensitive " + KEY)

    provider = AbuseIPDBProvider(config(), transport=httpx.MockTransport(timeout))
    result = provider.lookup_ip(IP)
    assert result.lookup_status == "timeout" and KEY not in result.model_dump_json()
    empty = Settings(_env_file=None)
    assert AbuseIPDBProvider(empty).lookup_ip(IP).lookup_status == "not_configured"
    empty.abuseipdb_enabled = False
    assert AbuseIPDBProvider(empty).lookup_ip(IP).lookup_status == "disabled"


@pytest.mark.parametrize(
    "body", [[], {}, {"data": {"ipAddress": "1.1.1.1", "abuseConfidenceScore": 100}}, "not json"]
)
def test_malformed_or_mismatched_provider_response(body):
    def handler(r):
        return (
            httpx.Response(200, text=body)
            if isinstance(body, str)
            else httpx.Response(200, json=body)
        )

    result = AbuseIPDBProvider(config(), transport=httpx.MockTransport(handler)).lookup_ip(IP)
    assert result.lookup_status == "invalid_response" and result.normalized_score is None


def test_missing_measurements_remain_unknown_and_undetected_not_safe():
    provider = VirusTotalProvider(config())
    assert (
        provider.normalize(IP, vt(malicious=0, suspicious=0, undetected=0)).reputation_level
        == "UNKNOWN"
    )
    no_adverse = provider.normalize(IP, vt(malicious=0, suspicious=0))
    assert (
        no_adverse.reputation_level == "NO_ADVERSE_SIGNALS" and "not safe" in no_adverse.explanation
    )
    payload = abuse()
    payload["data"].pop("abuseConfidenceScore")
    assert AbuseIPDBProvider(config()).normalize(IP, payload).normalized_score is None
    assert OTXProvider(config()).normalize(IP, {"indicator": IP}).reputation_level == "UNKNOWN"


def test_retry_after_seconds_date_and_bounded_transient_retry(monkeypatch):
    now = datetime.now(UTC)
    assert (retry_after("60") - now).total_seconds() >= 59
    future = now + timedelta(hours=1)
    assert abs((retry_after(format_datetime(future)) - future).total_seconds()) < 1
    assert retry_after("bad") is None
    settings = config()
    settings.threat_intelligence_max_retries = 1
    monkeypatch.setattr("app.threat_intelligence.providers.base.sleep", lambda delay: None)
    seen = []

    def handler(r):
        seen.append(r)
        return httpx.Response(503) if len(seen) == 1 else httpx.Response(200, json=abuse())

    provider = AbuseIPDBProvider(settings, transport=httpx.MockTransport(handler))
    assert provider.lookup_ip(IP).lookup_status == "success" and len(seen) == 2
    limited = AbuseIPDBProvider(
        settings,
        transport=httpx.MockTransport(
            lambda r: httpx.Response(429, headers={"Retry-After": "120"})
        ),
    )
    result = limited.lookup_ip(IP)
    assert limited.requests == 1 and result.retry_at >= now + timedelta(seconds=119)


def test_successful_payload_redaction_and_size_limit():
    payload = abuse()
    payload["api_key"] = KEY
    payload["data"]["isp"] = "echo " + KEY
    settings = config()
    settings.abuseipdb_api_key = SecretStr(" " + KEY + " ")
    result = AbuseIPDBProvider(
        settings, transport=httpx.MockTransport(lambda r: httpx.Response(200, json=payload))
    ).lookup_ip(IP)
    assert KEY not in result.model_dump_json() and "api_key" not in result.raw_response
    settings = config(threat_intelligence_max_response_bytes=1024)
    result = AbuseIPDBProvider(
        settings, transport=httpx.MockTransport(lambda r: httpx.Response(200, content=b"x" * 1025))
    ).lookup_ip(IP)
    assert result.lookup_status == "invalid_response"


def test_mock_determinism_reuses_existing_indicator_set():
    provider = MockProvider(config())
    for ip in LocalSyntheticReputationProvider.INDICATORS:
        a, b = provider.lookup_ip(ip), provider.lookup_ip(ip)
        assert a.model_dump(exclude={"checked_at", "expires_at"}) == b.model_dump(
            exclude={"checked_at", "expires_at"}
        )
        assert a.normalized_score == 92 and a.simulation and a.reports == 143
    assert provider.lookup_ip("192.0.2.1").reputation_level == "NO_ADVERSE_SIGNALS"
    assert provider.lookup_ip(IP).reputation_level == "UNKNOWN"
    assert provider.requests == 0


def test_aggregation_preserves_disagreement_partial_and_unknown():
    a = AbuseIPDBProvider(config())
    adverse = a.normalize(IP, abuse(score=90))
    clean = VirusTotalProvider(config()).normalize(IP, vt(malicious=0, suspicious=0))
    failure = OTXProvider(config()).result(IP, "timeout", "Provider timed out")
    result = aggregate(IP, "live", [adverse, clean, failure])
    assert result.reputation_level == "MALICIOUS" and result.normalized_score == 90
    assert (
        result.sources_checked == 2 and result.sources_with_adverse_signals == 1 and result.partial
    )
    unknown = aggregate(IP, "live", [clean, failure])
    assert unknown.reputation_level == "UNKNOWN" and unknown.malicious is None
    assert aggregate(IP, "live", [failure]).normalized_score is None


def test_nonfinite_json_and_unknown_cached_risk_explanation():
    from app.risk.components import reputation

    result = AbuseIPDBProvider(
        config(),
        transport=httpx.MockTransport(
            lambda r: httpx.Response(200, content=b'{"data":{"extra":1e999}}')
        ),
    ).lookup_ip(IP)
    assert result.lookup_status == "invalid_response" and result.raw_response == {}
    component = reputation({"reputation_context": [], "reputation_source": "cached"})
    assert component["points"] == 0 and "intelligence cache" in component["reason"]
