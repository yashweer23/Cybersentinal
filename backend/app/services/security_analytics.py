"""Phase 14 extends the existing scope/window aggregation layer, without mutations."""

from datetime import timedelta

from sqlalchemy import func, select, true

from app.models import ThreatIntelligenceResult as Intel
from app.repositories.analytics_entities import entity_statement
from app.repositories.analytics_repository import CATEGORY_RULES, AnalyticsRepository
from app.repositories.dashboard_repository import DashboardRepository, window
from app.repositories.synthetic_analytics import evaluate
from app.risk.config import SCORE_VERSION
from app.schemas import analytics as schema
from app.services.analytics_service import average, bucket_start, resolve_scope, timeline_interval
from app.threat_intelligence.service import ThreatIntelligenceService

DEFINITION = (
    "Events use occurrence timestamps; findings use last_seen; incidents use created_at. "
    "Case state and scores are current at query time, not historical "
    "snapshots. All ranges are [start,end) UTC."
)


def rate(n, d):
    return round(100 * n / d, 2) if d else None


def zero_fill(scope, seconds, rows, model):
    points = {r["timestamp"]: r for r in rows}
    current = bucket_start(scope.start, seconds)
    output = []
    while current < scope.end:
        output.append(model(**points.get(current, {"timestamp": current})))
        current += timedelta(seconds=seconds)
    return output


class SecurityAnalyticsService:
    def __init__(self, session, settings, scope=None):
        self.session, self.settings, self.fixed_scope = session, settings, scope
        self.repository = AnalyticsRepository(session)

    def execute(self, operation, query):
        with self.session.no_autoflush:
            scope = self.fixed_scope or resolve_scope(query, self.settings)
            return getattr(self, operation)(scope, query)

    def overview(self, s, q):
        values = self.repository.overview(s)
        for key in (
            "average_risk_score",
            "median_risk_score",
            "mean_time_to_acknowledge_seconds",
            "mean_time_to_resolve_seconds",
            "p90_resolution_seconds",
        ):
            values[key] = average(values[key])
        values["resolution_rate"] = rate(values["resolved_incidents"], values["incidents_created"])
        values["false_positive_rate"] = rate(
            values["false_positives"], values["resolved_incidents"] + values["false_positives"]
        )
        return schema.Overview(
            scope=s,
            definition=DEFINITION
            + " MTTA: first audited human INVESTIGATING transition since creation. "
            "MTTR: current RESOLVED cases with valid resolved_at. Rates are "
            "percentages.",
            **values,
        )

    def events(self, s, q):
        interval, seconds = timeline_interval(s)
        data = zero_fill(s, seconds, self.repository.event_trend(s, seconds, q), schema.EventPoint)
        return schema.EventTrend(
            scope=s,
            definition="Observed events matching all selected filters; event occurrence time.",
            interval=interval,
            bucket_seconds=seconds,
            total=sum(p.total for p in data),
            data=data,
        )

    def incidents(self, s, q):
        interval, seconds = timeline_interval(s)
        created, transitions = self.repository.incident_trend(s, seconds)
        points = {r["timestamp"]: dict(r) for r in created}
        for row in transitions:
            points.setdefault(row["timestamp"], {"timestamp": row["timestamp"]}).update(row)
        return schema.IncidentTrend(
            scope=s,
            definition="Created cases by creation time; critical uses current severity. "
            "Resolutions, false-positive closures and reopenings count canonical "
            "audited transitions in the period, including repeated closures and "
            "older cases. Not unique closed-case totals.",
            interval=interval,
            bucket_seconds=seconds,
            data=zero_fill(s, seconds, list(points.values()), schema.IncidentPoint),
        )

    def rules(self, s, q):
        rows = self.repository.rules(s)
        for row in rows:
            row["average_risk"] = average(row["average_risk"])
            row["false_positive_rate"] = rate(row["false_positives"], row["closed_incidents"])
        return schema.RulePerformance(
            scope=s,
            definition=DEFINITION
            + " Each associated case counts once per rule. Average risk uses one "
            "current-version assessment per finding. False-positive rate = FP / "
            "(RESOLVED + FP); not detection accuracy.",
            items=rows,
        )

    def risk_trend(self, s, q):
        interval, seconds = timeline_interval(s)
        rows = self.repository.risk_trend(s, seconds, q.population)
        for row in rows:
            for key in ("average_risk", "median_risk"):
                row[key] = average(row[key])
        return schema.RiskTrend(
            scope=s,
            definition="Current scores grouped by case creation or finding last_seen. This "
            "is a cohort profile, not a reconstruction of past score changes. "
            "Missing scores are excluded; empty buckets have null statistics.",
            population=q.population,
            score_version=SCORE_VERSION,
            interval=interval,
            bucket_seconds=seconds,
            data=zero_fill(s, seconds, rows, schema.RiskPoint),
        )

    def histogram(self, s, q):
        bands = self.repository.histogram(s, q.population)
        data = [
            {"label": f"{i * 10}–{100 if i == 9 else i * 10 + 9}", "count": bands.get(i, 0)}
            for i in range(10)
        ]
        return schema.Histogram(
            scope=s,
            definition="Current scores; one current algorithm-version assessment per "
            "finding, or the stored current incident score. 90–100 includes 100.",
            population=q.population,
            total=sum(b["count"] for b in data),
            data=data,
        )

    def entities(self, s, q):
        intel = ThreatIntelligenceService(
            self.session, self.settings, mock=None if q.mode is None else q.mode == "mock"
        )
        rows = self.repository.rows(
            entity_statement(s, q.kind, q.limit, q.recurring_only, intel.mode, intel.policy_hash())
        )
        for row in rows:
            row["average_risk"] = average(row["average_risk"])
            row["detection_rules"] = sorted(row["detection_rules"] or [])
        return schema.EntityAnalytics(
            scope=s,
            definition=DEFINITION + " Deduplicated associated accounts/IPs/assets, not malicious "
            "identities. Average risk uses current case scores; highest risk "
            "includes current finding scores. Suspicious events means retained "
            "finding-linked events in range. Rankings: highest risk, case count, "
            "finding count, entity.",
            kind=q.kind,
            items=rows[: q.limit],
            limit=q.limit,
            has_more=len(rows) > q.limit,
        )

    def backlog(self, s, q):
        values = self.repository.backlog(s)
        values["average_age_seconds"] = average(values["average_age_seconds"])
        return schema.Backlog(
            scope=s,
            definition="Current OPEN/INVESTIGATING backlog of cases CREATED in the selected "
            "period. Age is measured to scope.as_of, not the period end. Not a "
            "historical backlog snapshot.",
            **values,
        )

    def workload(self, s, q):
        _, seconds = timeline_interval(s)
        limit, offset = getattr(q, "limit", 100), getattr(q, "offset", 0)
        values = self.repository.workload(s, seconds, limit, offset)
        values.update(limit=limit, offset=offset, has_more=len(values["items"]) > limit)
        values["items"] = values["items"][:limit]
        for item in values["items"]:
            item["average_resolution_seconds"] = average(item["average_resolution_seconds"])
        values["activity"] = zero_fill(s, seconds, values["activity"], schema.ActivityPoint)
        return schema.Workload(
            scope=s,
            definition="Active ADMIN/ANALYST accounts in username order. Counts use current "
            "assignment for the creation-time case cohort; resolution time is "
            "not individual performance or resolver attribution. Activity counts "
            "audited human actions occurring in the period.",
            **values,
        )

    def categories(self, s, q):
        findings, cases = self.repository.categories(s)
        values = {
            name: {"category": name, "findings": 0, "incidents": 0} for name in CATEGORY_RULES
        }
        for row in findings + cases:
            values.setdefault(
                row["category"], {"category": row["category"], "findings": 0, "incidents": 0}
            ).update(row)
        return schema.Categories(
            scope=s,
            definition=DEFINITION
            + " Fixed rule mapping. A case can belong to multiple categories, so "
            "category totals are not additive.",
            items=list(values.values()),
        )

    def geography(self, s, q):
        rows = self.repository.geography(s)
        return schema.Geography(
            scope=s,
            definition="Observed Source Geography: nonempty country values supplied in "
            "retained evidence. Unverified log metadata, not IP geolocation or "
            "attacker/nation attribution. A finding/case can appear in multiple "
            "countries. Incidents must also match the creation cohort.",
            items=rows[:30],
            has_more=len(rows) > 30,
        )

    def intelligence(self, s, q):
        modes = []
        old = DashboardRepository(self.session)
        for mode in ("mock", "live"):
            provider = ThreatIntelligenceService(self.session, self.settings, mock=mode == "mock")
            totals = old.threats(s, mode, provider.policy_hash())
            providers = (
                func.jsonb_array_elements(Intel.payload["providers"])
                .table_valued("value")
                .render_derived()
                .lateral("providers")
            )
            name = providers.c.value.op("->>")("provider")
            status = providers.c.value.op("->>")("lookup_status")
            usage = self.repository.rows(
                select(
                    name.label("provider"),
                    status.label("lookup_status"),
                    func.count().label("bundles"),
                )
                .select_from(Intel)
                .join(providers, true())
                .where(
                    Intel.mode == mode,
                    *window(Intel.checked_at, s),
                    name.is_not(None),
                    status.is_not(None),
                )
                .group_by(name, status)
                .order_by(name, status)
            )
            modes.append(
                dict(
                    mode=mode,
                    simulation=mode == "mock",
                    indicators_checked=totals["cached_indicators"],
                    malicious=totals["malicious_indicators"],
                    suspicious=totals["suspicious_indicators"],
                    unknown=totals["unknown_indicators"],
                    no_adverse_signals=totals["no_adverse_signal_indicators"],
                    expired=totals["expired_indicators"],
                    cache_hits=totals["cache_hits"],
                    lookups=int(self.repository.metric(s, "threat_lookup_count", mode)),
                    provider_failures=int(
                        self.repository.metric(s, "threat_provider_errors", mode)
                    ),
                    provider_usage=usage,
                )
            )
        return schema.IntelligenceAnalytics(
            scope=s,
            definition="Separate mock/live current cache bundles whose latest check is in "
            "range. Expired/incompatible evidence is UNKNOWN. Provider usage "
            "counts provider entries in retained bundles, not lifetime requests. "
            "Lookup/cache/error totals come from recorded period metrics. No "
            "external calls.",
            modes=modes,
        )

    def ai(self, s, q):
        values = self.repository.ai_usage(s)
        values["average_response_ms"] = average(values["average_response_ms"])
        return schema.AIUsage(
            scope=s,
            definition="Saved analyses by generated_at and request metrics by timestamp. "
            "Failure counts are recorded provider-failure fallbacks; unrecorded "
            "database failures are not inferred. Exact global staleness is "
            "unavailable without rebuilding every case context.",
            **values,
        )

    def evaluation(self, s, q):
        v = evaluate(self.session, s)
        agreeing = v.pop("agreeing")
        v.update(
            missed_scenarios=v["expected_scenarios"] - v["detected_scenarios"],
            unexpected_findings=v["findings_evaluated"] - agreeing,
            scenario_recall=v["detected_scenarios"] / v["expected_scenarios"]
            if v["expected_scenarios"]
            else None,
            finding_label_agreement=agreeing / v["findings_evaluated"]
            if v["findings_evaluated"]
            else None,
        )
        return schema.SyntheticEvaluation(
            scope=s,
            definition="Generator-labelled evidence only. Expected units are distinct "
            "(rule, scenario_id) with events in range; findings must have "
            "last_seen in range and retained synthetic evidence in range. Recall "
            "measures covered expected units. Boundary truncation and "
            "overlapping behavior limit interpretation. Not real-world accuracy.",
            **v,
        )

    def status_history(self, s, q):
        from app.repositories.analytics_repository import status_history_statement

        interval, seconds = timeline_interval(s)
        statement, coverage = status_history_statement(s, seconds)
        rows = self.repository.rows(statement)
        for row in rows:
            row["unresolved"] = row["open"] + row["investigating"]
        return schema.StatusHistory(
            scope=s,
            definition="Recorded lifecycle state at each UTC bucket end, capped at period "
            "end/as_of, for cases CREATED in the selected period with an "
            "INCIDENT_CREATED audit. Creation establishes OPEN under the "
            "existing workflow; canonical status audits supply later states. "
            "Cases lacking a creation audit are excluded, not inferred from "
            "current status. Audit gaps/out-of-band edits can differ from the "
            "live backlog.",
            interval=interval,
            bucket_seconds=seconds,
            data=zero_fill(s, seconds, rows, schema.StatusPoint),
            **self.repository.one(coverage),
        )
