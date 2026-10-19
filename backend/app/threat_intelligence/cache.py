"""Extend the Phase 2 cache identity; mode-specific bundles are authoritative."""

from datetime import UTC, datetime, timedelta

from sqlalchemy import func, select
from sqlalchemy.dialects.postgresql import insert

from app.core.enums import IndicatorType
from app.models import ThreatIntelligence, ThreatIntelligenceResult
from app.repositories.threat_cache import store_cached_indicator
from app.schemas.threat_intelligence import ThreatIntelligenceCreate
from app.threat_intelligence.schemas import IntelligenceResponse


def snapshot(session, ip, mode):
    return session.scalar(
        select(ThreatIntelligenceResult)
        .join(ThreatIntelligence)
        .where(
            ThreatIntelligence.indicator == ip,
            ThreatIntelligence.indicator_type == IndicatorType.IP,
            ThreatIntelligenceResult.mode == mode,
        )
        .execution_options(populate_existing=True)
    )


def response(row, policy_hash, *, compact=False):
    result = IntelligenceResponse.model_validate(row.payload)
    result.cache_hit = True
    result.stale = row.expires_at <= datetime.now(UTC)
    result.configuration_changed = row.policy_hash != policy_hash
    result.external_requests = result.provider_evaluations = result.duration_ms = 0
    result.provider_cache_hits = len(result.providers)
    if compact:
        for provider in result.providers:
            provider.raw_response = {}
    return result


def persist(session, result, policy_hash):
    abuse = next(
        (p for p in result.providers if p.provider in {"AbuseIPDB", "CyberSentinel Mock"}), None
    )
    countries = sorted({p.country for p in result.providers if p.country})
    isps = sorted({p.isp for p in result.providers if p.isp})
    row = store_cached_indicator(
        session,
        ThreatIntelligenceCreate(
            indicator=result.indicator,
            indicator_type=IndicatorType.IP,
            malicious=result.malicious,
            abuse_score=abuse.provider_score if abuse else None,
            confidence_score=None,
            reports=abuse.reports if abuse else None,
            country=countries[0] if len(countries) == 1 else None,
            isp=isps[0] if len(isps) == 1 else None,
            source=[p.provider for p in result.providers],
            raw_response={
                "mode": result.mode,
                "reputation_level": result.reputation_level,
                "normalized_score": result.normalized_score,
                "simulation": result.simulation,
                "provider_results_table": "threat_intelligence_results",
            },
            first_seen=result.checked_at,
            last_checked=result.checked_at,
            expires_at=max(result.expires_at, result.checked_at + timedelta(microseconds=1)),
        ),
    )
    result.first_seen = row.first_seen
    values = dict(
        indicator_id=row.id,
        mode=result.mode,
        reputation_level=result.reputation_level,
        normalized_score=result.normalized_score,
        malicious=result.malicious,
        policy_hash=policy_hash,
        payload=result.model_dump(mode="json"),
        checked_at=result.checked_at,
        expires_at=result.expires_at,
    )
    statement = insert(ThreatIntelligenceResult).values(**values)
    session.execute(
        statement.on_conflict_do_update(
            index_elements=["indicator_id", "mode"],
            set_={
                k: getattr(statement.excluded, k)
                for k in values
                if k not in {"indicator_id", "mode"}
            },
            where=statement.excluded.checked_at >= ThreatIntelligenceResult.checked_at,
        )
    )


def list_cached(session, filters, mode):
    conditions = [ThreatIntelligenceResult.mode == mode]
    if filters.indicator:
        conditions.append(ThreatIntelligence.indicator == filters.indicator)
    for field in ("reputation_level", "malicious"):
        value = getattr(filters, field)
        if value is not None:
            conditions.append(getattr(ThreatIntelligenceResult, field) == value)
    if filters.last_checked:
        conditions.append(ThreatIntelligenceResult.checked_at >= filters.last_checked)
    if filters.provider:
        conditions.append(
            ThreatIntelligenceResult.payload["providers"].contains([{"provider": filters.provider}])
        )
    statement = select(ThreatIntelligenceResult).join(ThreatIntelligence).where(*conditions)
    total = session.scalar(select(func.count()).select_from(statement.subquery()))
    rows = session.scalars(
        statement.order_by(ThreatIntelligenceResult.checked_at.desc(), ThreatIntelligenceResult.id)
        .offset(filters.offset)
        .limit(filters.limit)
    ).all()
    return rows, total
