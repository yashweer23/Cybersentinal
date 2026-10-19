"""Dashboard metric definitions and projections, with no processing side effects."""

import logging
from datetime import UTC, datetime
from time import perf_counter

from sqlalchemy.exc import SQLAlchemyError

from app.ai.service import ai_status
from app.core.enums import IncidentStatus, SeverityLevel
from app.core.errors import ServiceError
from app.models import Incident
from app.repositories.dashboard_repository import DashboardRepository
from app.risk.config import SCORE_VERSION
from app.schemas import dashboard as schema
from app.services.analytics_service import average, fill_timeline, resolve_scope, timeline_interval
from app.threat_intelligence.service import ThreatIntelligenceService

logger = logging.getLogger(__name__)
SEVERITIES = tuple(reversed(tuple(SeverityLevel)))


class DashboardService:
    def __init__(self, session, settings):
        self.session, self.settings = session, settings
        self.repository = DashboardRepository(session)

    def execute(self, operation, query=None):
        started = perf_counter()
        try:
            # Prevent accidental flushes even when called with an existing ORM session.
            with self.session.no_autoflush:
                return getattr(self, operation)(query)
        except SQLAlchemyError as exc:
            logger.warning(
                "Dashboard query failed operation=%s error=%s", operation, type(exc).__name__
            )
            raise
        except ServiceError as exc:
            logger.info(
                "Dashboard request rejected operation=%s status=%d", operation, exc.status_code
            )
            raise
        finally:
            elapsed = (perf_counter() - started) * 1000
            if elapsed >= self.settings.dashboard_slow_query_ms:
                logger.warning(
                    "Slow dashboard query operation=%s duration_ms=%.3f", operation, elapsed
                )

    def scope(self, query):
        return resolve_scope(query, self.settings)

    def intelligence(self, mode=None):
        return ThreatIntelligenceService(
            self.session, self.settings, mock=None if mode is None else mode == "mock"
        )

    def overview(self, query):
        scope = self.scope(query)
        values = self.repository.overview(scope)
        values["average_risk_score"] = average(values["average_risk_score"])
        return schema.DashboardOverviewResponse(scope=scope, **values)

    def timeline(self, query):
        scope = self.scope(query)
        interval, seconds = timeline_interval(scope)
        data = fill_timeline(scope, seconds, self.repository.timeline(scope, seconds))
        return schema.SecurityTimelineResponse(
            scope=scope,
            interval=interval,
            bucket_seconds=seconds,
            total=sum(item.total for item in data),
            data=data,
        )

    def event_types(self, query):
        scope = self.scope(query)
        values = self.repository.event_types(scope)
        return schema.EventTypeDistributionResponse(
            scope=scope, total=sum(row["count"] for row in values), distribution=values
        )

    def severity(self, query):
        scope = self.scope(query)
        values = self.repository.distribution(scope, Incident.severity)
        return schema.SeverityDistributionResponse(
            scope=scope,
            total=sum(values.values()),
            distribution=[{"severity": key, "count": values.get(key, 0)} for key in SEVERITIES],
        )

    def status(self, query):
        scope = self.scope(query)
        values = self.repository.distribution(scope, Incident.status)
        return schema.StatusDistributionResponse(
            scope=scope,
            total=sum(values.values()),
            distribution=[{"status": key, "count": values.get(key, 0)} for key in IncidentStatus],
        )

    def risk_distribution(self, query):
        scope = self.scope(query)
        values = self.repository.risk_distribution(scope)
        counts = {row["level"]: row["count"] for row in values}
        total = sum(counts.values())
        score_sum = sum(row["score_sum"] for row in values)
        return schema.RiskDistributionResponse(
            scope=scope,
            total=total,
            average_risk_score=round(score_sum / total, 2) if total else None,
            distribution=[{"level": key, "count": counts.get(key, 0)} for key in SEVERITIES],
        )

    def recent_events(self, query):
        scope = self.scope(query)
        # Capture BEFORE the table projection: concurrent arrivals may repeat, never get skipped.
        cursor = self.repository.event_head()
        return schema.RecentEventsResponse(
            scope=scope,
            items=self.repository.recent_events(scope, query.limit),
            limit=query.limit,
            polling_cursor=cursor,
        )

    def updates(self, query):
        head = self.repository.event_head()
        if query.after_id is None:
            return schema.EventUpdatesResponse(
                items=[], next_cursor=head, head_cursor=head, has_more=False, initialized=True
            )
        if query.after_id > head:
            raise ServiceError(
                422, "Polling cursor is ahead of this database; initialize a new cursor"
            )
        rows = self.repository.event_updates(query.after_id, head, query.limit)
        items = rows[: query.limit]
        return schema.EventUpdatesResponse(
            items=items,
            next_cursor=items[-1]["ingestion_sequence"] if items else query.after_id,
            head_cursor=head,
            has_more=len(rows) > query.limit,
        )

    def recent_incidents(self, query):
        scope = self.scope(query)
        return schema.RecentIncidentsResponse(
            scope=scope,
            items=self.repository.recent_incidents(scope, query.limit),
            limit=query.limit,
        )

    def top_ips(self, query):
        scope, intelligence = self.scope(query), self.intelligence(query.mode)
        return schema.TopSuspiciousIPsResponse(
            scope=scope,
            mode=intelligence.mode,
            limit=query.limit,
            finding_score_version=SCORE_VERSION,
            items=self.repository.top_ips(
                scope, intelligence.mode, intelligence.policy_hash(), query.limit
            ),
        )

    def targeted_users(self, query):
        scope = self.scope(query)
        return schema.TargetedUsersResponse(
            scope=scope, items=self.repository.targeted_users(scope, query.limit), limit=query.limit
        )

    def rules(self, query):
        scope = self.scope(query)
        return schema.DetectionRuleStatsResponse(scope=scope, items=self.repository.rules(scope))

    def threats(self, query):
        scope, intelligence = self.scope(query), self.intelligence(query.mode)
        return schema.ThreatSummaryResponse(
            scope=scope,
            mode=intelligence.mode,
            simulation=intelligence.mode == "mock",
            providers=intelligence.provider_status(),
            **self.repository.threats(scope, intelligence.mode, intelligence.policy_hash()),
        )

    def activity(self, query):
        scope = self.scope(query)
        return schema.ActivitySummaryResponse(scope=scope, **self.repository.activity(scope))

    def health(self, query=None):
        values = self.repository.health()
        return schema.DashboardHealthResponse(
            as_of=datetime.now(UTC),
            total_events=values["total_events"],
            latest_event_timestamp=values["latest_event_timestamp"],
            detection_engine={
                "events_processed": values["total_events"] - values["unprocessed_events"],
                "unprocessed_events": values["unprocessed_events"],
                "last_processing_time": values["last_processing_time"],
                "last_processing_duration_ms": values["last_processing_duration_ms"],
            },
            threat_intelligence=self.intelligence().provider_status(),
            ai_analyst=ai_status(self.settings, self.session),
        )
