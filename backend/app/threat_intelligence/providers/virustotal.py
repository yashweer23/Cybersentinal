from urllib.parse import quote

from app.threat_intelligence.providers.base import HTTPProvider
from app.threat_intelligence.utils.normalization import integer, same_ip, string, tags, timestamp


class VirusTotalProvider(HTTPProvider):
    name, host = "VirusTotal", "www.virustotal.com"
    key_setting, enabled_setting, header = "virustotal_api_key", "virustotal_enabled", "x-apikey"

    def endpoint(self, target):
        return "https://www.virustotal.com/api/v3/ip_addresses/" + quote(target.ip, safe=""), None

    def normalize(self, ip, payload):
        data = payload.get("data")
        if (
            not isinstance(data, dict)
            or data.get("type") != "ip_address"
            or not same_ip(data.get("id"), ip)
        ):
            raise ValueError()
        data = data.get("attributes")
        if not isinstance(data, dict):
            raise ValueError()
        stats = data.get("last_analysis_stats", {})
        if not isinstance(stats, dict):
            stats = {}
        malicious, suspicious = integer(stats.get("malicious")), integer(stats.get("suspicious"))
        total = sum(
            integer(stats.get(k)) or 0
            for k in ("malicious", "suspicious", "harmless", "undetected")
        )
        level, score = "UNKNOWN", None
        if malicious is not None and malicious >= 3:
            level, score = "MALICIOUS", min(100, 75 + 5 * (malicious - 3))
        elif malicious or suspicious:
            level, score = "SUSPICIOUS", min(74, 40 + 10 * (malicious or 0) + 5 * (suspicious or 0))
        elif malicious == suspicious == 0 and total > 0:
            level, score = "NO_ADVERSE_SIGNALS", 0
        return self.result(
            ip,
            "unknown" if score is None else "success",
            "Engine-count policy: at least 3 malicious engines maps to 75+; fewer "
            "adverse engines map below 75. Counts and community reputation are retained "
            "separately. Undetected is not safe.",
            provider_score=integer(data.get("reputation"), low=-2147483648),
            normalized_score=score,
            reputation_level=level,
            malicious=True if level == "MALICIOUS" else False if score == 0 else None,
            country=string(data.get("country"), 100),
            isp=string(data.get("as_owner")),
            tags=tags(data.get("tags")),
            last_seen=timestamp(data.get("last_analysis_date")),
            raw_response=payload,
        )
