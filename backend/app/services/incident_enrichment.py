"""Associate cache by canonical IP using existing finding/evidence foreign keys."""

from time import perf_counter
from uuid import uuid4

from sqlalchemy import func, select, union

from app.core.errors import ServiceError
from app.models import DetectionFinding, Incident, IncidentEvidence, IncidentFinding, SecurityEvent
from app.services.audit_service import record_audit
from app.threat_intelligence.aggregator import FAILURES
from app.threat_intelligence.schemas import EnrichmentSummary, RelatedIntelligence, RelatedQuery


def related_entity(session, identifier, kind):
    model = Incident if kind == "incident" else DetectionFinding
    column = model.incident_id if kind == "incident" else model.finding_id
    row = session.scalar(select(model).where(column == identifier))
    if row is None:
        raise ServiceError(
            404, "Incident not found" if kind == "incident" else "Detection finding not found"
        )
    return row


def indicator_query(session, identifier, kind):
    row = related_entity(session, identifier, kind)
    if kind == "incident":
        base = [
            select(Incident.source_ip.label("ip")).where(Incident.id == row.id),
            select(DetectionFinding.source_ip.label("ip"))
            .join(IncidentFinding, IncidentFinding.detection_finding_id == DetectionFinding.id)
            .where(IncidentFinding.incident_id == row.id),
        ]
        for field in (SecurityEvent.source_ip, SecurityEvent.destination_ip):
            base.append(
                select(field.label("ip"))
                .join(IncidentEvidence, IncidentEvidence.security_event_id == SecurityEvent.id)
                .where(IncidentEvidence.incident_id == row.id)
            )
    else:
        # Detection evidence is bounded by Phase 6; never inspect simulation labels.
        ids = row.evidence_event_ids if isinstance(row.evidence_event_ids, list) else []
        if len(ids) > 200 or any(not isinstance(value, str) for value in ids):
            raise ServiceError(422, "Finding evidence identifiers are invalid")
        base = [select(DetectionFinding.source_ip.label("ip")).where(DetectionFinding.id == row.id)]
        for field in (SecurityEvent.source_ip, SecurityEvent.destination_ip):
            base.append(select(field.label("ip")).where(SecurityEvent.event_id.in_(ids)))
    values = union(*base).subquery()
    return select(values.c.ip).where(values.c.ip.is_not(None)).order_by(values.c.ip)


def read_related(service, identifier, kind, query=None):
    query = query or RelatedQuery()
    statement = indicator_query(service.session, identifier, kind)
    total = service.session.scalar(select(func.count()).select_from(statement.subquery()))
    indicators, missing = [], []
    for value in service.session.scalars(statement.offset(query.offset).limit(query.limit)):
        result = service.get_cached_intelligence(str(value), mode=query.mode, compact=True)
        if result:
            indicators.append(result)
        else:
            missing.append(str(value))
    return RelatedIntelligence(
        entity_id=identifier,
        entity_type=kind,
        mode=query.mode or service.mode,
        indicators=indicators,
        missing_indicators=missing,
        total_indicators=total,
        limit=query.limit,
        offset=query.offset,
    )


def enrich_incidents(service, options, *, actor_id=None, ip_address=None):
    started = perf_counter()
    settings, session = service.settings, service.session
    if options.limit > settings.threat_intelligence_max_incidents:
        raise ServiceError(422, "Requested limit exceeds configured incident-enrichment maximum")
    statement = select(Incident.incident_id).order_by(Incident.created_at.desc(), Incident.id)
    if options.incident_id:
        related_entity(session, options.incident_id, "incident")
        statement = statement.where(Incident.incident_id == options.incident_id)
    cases = list(session.scalars(statement.offset(options.offset).limit(options.limit + 1)))
    more = len(cases) > options.limit
    cases = cases[: options.limit]
    mapping = {}
    # Resolve bounded references before any provider request or cache write.
    for identifier in cases:
        values = {
            str(ip)
            for ip in session.scalars(
                indicator_query(session, identifier, "incident").limit(
                    settings.threat_intelligence_max_indicators + 1
                )
            )
        }
        mapping[identifier] = values
        if len(set().union(*mapping.values())) > settings.threat_intelligence_max_indicators:
            raise ServiceError(
                422, "Too many unique indicators; reduce limit or enrich a smaller case selection"
            )
    unique = sorted(set().union(*mapping.values())) if mapping else []
    summary = EnrichmentSummary(
        mode=service.mode,
        simulation=service.mode == "mock",
        incidents_evaluated=len(cases),
        unique_indicators=len(unique),
        next_offset=options.offset + len(cases) if more else None,
    )
    results = {}
    for ip in unique:
        if perf_counter() - started >= settings.threat_intelligence_run_timeout_seconds:
            summary.complete = False
            summary.error = (
                "Enrichment time budget reached; repeat to reuse completed cache entries"
            )
            summary.next_offset = options.offset
            break
        try:
            result = service.lookup_ip(ip, force_refresh=options.force_refresh, record=False)
        except ServiceError as exc:
            summary.complete = False
            summary.error = exc.detail
            summary.next_offset = options.offset
            break
        summary.indicators_evaluated += 1
        for provider in result.providers:
            provider.raw_response = {}
        results[ip] = result
        summary.cache_hits += int(result.cache_hit)
        summary.external_lookups += int(result.external_requests > 0)
        summary.provider_requests += result.external_requests
        summary.provider_evaluations += result.provider_evaluations
        summary.failed_lookups += int(any(p.lookup_status in FAILURES for p in result.providers))
        summary.unknown_lookups += int(result.reputation_level == "UNKNOWN")
    summary.incidents_enriched = sum(
        any(ip in results and results[ip].sources_checked > 0 for ip in values)
        for values in mapping.values()
    )
    summary.duration_ms = round((perf_counter() - started) * 1000, 3)
    record_audit(
        session,
        "INCIDENT_ENRICHMENT_TRIGGERED",
        actor_id=actor_id,
        entity_type="threat_enrichment",
        entity_id=options.incident_id or str(uuid4()),
        ip_address=ip_address,
        new_value={**summary.model_dump(mode="json"), "force_refresh": options.force_refresh},
    )
    service.metrics(
        {
            "threat_lookup_count": summary.indicators_evaluated,
            "threat_cache_hits": summary.cache_hits,
            "threat_provider_errors": sum(
                p.lookup_status in FAILURES for r in results.values() for p in r.providers
            ),
            "threat_enrichment_duration_ms": summary.duration_ms,
            "incidents_enriched": summary.incidents_enriched,
        }
    )
    session.commit()
    return summary
