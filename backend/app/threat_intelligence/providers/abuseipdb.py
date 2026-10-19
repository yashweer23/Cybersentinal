from app.threat_intelligence.providers.base import HTTPProvider
from app.threat_intelligence.utils.normalization import integer, same_ip, string, timestamp


class AbuseIPDBProvider(HTTPProvider):
    name, host = "AbuseIPDB", "api.abuseipdb.com"
    key_setting, enabled_setting, header = "abuseipdb_api_key", "abuseipdb_enabled", "Key"

    def endpoint(self, target):
        return "https://api.abuseipdb.com/api/v2/check", {
            "ipAddress": target.ip,
            "maxAgeInDays": 90,
        }

    def normalize(self, ip, payload):
        data = payload.get("data")
        if not isinstance(data, dict) or not same_ip(data.get("ipAddress"), ip):
            raise ValueError()
        score = integer(data.get("abuseConfidenceScore"), high=100)
        level = (
            "UNKNOWN"
            if score is None
            else "MALICIOUS"
            if score >= 75
            else "SUSPICIOUS"
            if score
            else "NO_ADVERSE_SIGNALS"
        )
        return self.result(
            ip,
            "unknown" if score is None else "success",
            "Abuse confidence retained as 0–100: 75+ malicious signal, 1–74 suspicious, "
            "zero no reported adverse score; not a compromise probability.",
            provider_score=score,
            normalized_score=score,
            reputation_level=level,
            malicious=score >= 75 if score is not None else None,
            reports=integer(data.get("totalReports")),
            country=string(data.get("countryCode"), 100),
            isp=string(data.get("isp")),
            last_seen=timestamp(data.get("lastReportedAt")),
            raw_response=payload,
        )
