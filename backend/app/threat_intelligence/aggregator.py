from app.threat_intelligence.schemas import IntelligenceResponse

FAILURES = {"auth_error", "rate_limited", "timeout", "provider_error", "invalid_response"}


def aggregate(ip, mode, providers):
    successful = [p for p in providers if p.lookup_status == "success"]
    adverse = [p for p in successful if p.reputation_level in {"MALICIOUS", "SUSPICIOUS"}]
    partial = any(p.lookup_status != "success" for p in providers)
    level = "UNKNOWN"
    if any(p.reputation_level == "MALICIOUS" for p in adverse):
        level = "MALICIOUS"
    elif adverse:
        level = "SUSPICIOUS"
    elif successful and not any(
        p.lookup_status in FAILURES | {"unknown", "not_found"} for p in providers
    ):
        level = "NO_ADVERSE_SIGNALS"
    score = max(
        (p.normalized_score for p in successful if p.normalized_score is not None), default=None
    )
    if level == "UNKNOWN":
        score = None
    return IntelligenceResponse(
        indicator=ip,
        mode=mode,
        simulation=mode == "mock",
        data_label="SIMULATED DEMO DATA"
        if mode == "mock"
        else "REAL PROVIDER DATA / LOOKUP STATUS",
        lookup_status="not_applicable"
        if all(p.lookup_status == "not_applicable" for p in providers)
        else "partial"
        if successful and partial
        else "success"
        if successful
        else "unknown",
        reputation_level=level,
        normalized_score=score,
        malicious=True
        if level == "MALICIOUS"
        else False
        if level == "NO_ADVERSE_SIGNALS"
        else None,
        sources_checked=len(successful),
        sources_with_adverse_signals=len(adverse),
        partial=partial,
        explanation=(
            "Maximum available provider signal, not an average or a probability. "
            "Provider-specific mappings and raw values are retained. "
            "No adverse signals does not establish safety; failed coverage remains unknown."
        ),
        providers=providers,
        checked_at=max(p.checked_at for p in providers),
        expires_at=min(p.expires_at for p in providers),
    )
