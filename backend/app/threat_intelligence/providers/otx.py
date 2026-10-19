from urllib.parse import quote

from app.threat_intelligence.providers.base import HTTPProvider
from app.threat_intelligence.utils.normalization import integer, same_ip, string, tags, timestamp


class OTXProvider(HTTPProvider):
    name, host = "AlienVault OTX", "otx.alienvault.com"
    key_setting, enabled_setting, header = "otx_api_key", "otx_enabled", "X-OTX-API-KEY"

    def endpoint(self, target):
        return (
            f"https://otx.alienvault.com/api/v1/indicators/IPv{target.version}/"
            f"{quote(target.ip, safe='')}/general",
            None,
        )

    def normalize(self, ip, payload):
        if not same_ip(payload.get("indicator"), ip):
            raise ValueError()
        info = payload.get("pulse_info", {})
        if not isinstance(info, dict):
            info = {}
        count = integer(info.get("count"))
        pulses = info.get("pulses", [])
        labels = []
        if isinstance(pulses, list):
            for pulse in pulses[:100]:
                if isinstance(pulse, dict):
                    labels.extend(tags(pulse.get("tags")))
        level = "UNKNOWN" if count is None else "SUSPICIOUS" if count else "NO_ADVERSE_SIGNALS"
        score = None if count is None else min(74, 25 + 5 * count) if count else 0
        return self.result(
            ip,
            "unknown" if count is None else "success",
            "Pulse association alone is contextual suspicion, not verified "
            "maliciousness. Positive count maps to min(74, 25 + 5 × pulses); zero is no "
            "known pulse association.",
            normalized_score=score,
            reputation_level=level,
            malicious=False if count == 0 else None,
            country=string(payload.get("country_code"), 100),
            isp=string(payload.get("asn")),
            tags=tags(labels),
            last_seen=timestamp(payload.get("last_seen")),
            raw_response=payload,
        )
