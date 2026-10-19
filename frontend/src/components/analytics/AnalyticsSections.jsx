import { useState } from "react";
import { Link } from "react-router-dom";
import { useAuth } from "../../context/AuthContext";
import { useAnalyticsQuery } from "../../hooks/useAnalytics";
import { Badge, DataTable, Panel, QueryState, RiskBadge } from "../common/UI";
import { number, utc } from "../../utils/format";
import { TrendChart, ComparisonChart } from "./AnalyticsCharts";
export const duration = (v) =>
  v == null
    ? "—"
    : v < 60
      ? `${number(v, 1)} s`
      : v < 3600
        ? `${number(v / 60, 1)} min`
        : v < 86400
          ? `${number(v / 3600, 1)} h`
          : `${number(v / 86400, 1)} days`;
export const percent = (v) => (v == null ? "—" : `${number(v, 1)}%`);
export function Stat({ label, value, note }) {
  return (
    <article className="analytics-stat" title={note}>
      <span>{label}</span>
      <strong>{value}</strong>
      {note && <small>{note}</small>}
    </article>
  );
}
export function Definition({ data }) {
  return (
    <details className="analytics-definition">
      <summary>Scope & metric definition</summary>
      <p>{data.definition}</p>
      <p>As of {utc(data.scope.as_of)}</p>
    </details>
  );
}
export function Executive({ period }) {
  const overview = useAnalyticsQuery("overview", period),
    incidents = useAnalyticsQuery("incidents/trend", period),
    risk = useAnalyticsQuery("risk/trend", period);
  return (
    <>
      <QueryState query={overview}>
        {(d) => (
          <>
            <div className="analytics-kpis">
              <Stat
                label="Incidents created"
                value={number(d.incidents_created)}
                note="Creation-time cohort"
              />
              <Stat
                label="Critical incidents"
                value={number(d.critical_incidents)}
                note="Current case severity"
              />
              <Stat
                label="Resolution rate"
                value={percent(d.resolution_rate)}
                note="Resolved / all cohort cases"
              />
              <Stat
                label="Mean time to resolve"
                value={duration(d.mean_time_to_resolve_seconds)}
                note={`${d.measured_resolutions} resolved cases with valid timing`}
              />
              <Stat
                label="False-positive rate"
                value={percent(d.false_positive_rate)}
                note="False positives / closed cases"
              />
              <Stat
                label="Average risk"
                value={number(d.average_risk_score, 1)}
                note="Current case scores"
              />
            </div>
            <div className="analytics-volume">
              <span>
                <b>{number(d.total_events)}</b> security events
              </span>
              <span>
                <b>{number(d.detection_findings)}</b> detection findings
              </span>
              <span>
                <b>{number(d.unique_suspicious_ips)}</b> associated IPs
              </span>
              <span>
                <b>{number(d.unique_targeted_users)}</b> associated accounts
              </span>
            </div>
            <div className="analytics-response">
              <Stat
                label="Mean time to acknowledge"
                value={duration(d.mean_time_to_acknowledge_seconds)}
                note={`First audited INVESTIGATING transition · ${d.acknowledged_incidents} cases`}
              />
              <Stat
                label="P90 resolution time"
                value={duration(d.p90_resolution_seconds)}
                note="90th percentile of valid resolved-case durations"
              />
              <Stat
                label="Median incident risk"
                value={number(d.median_risk_score, 1)}
                note="Current case scores, not past score snapshots"
              />
            </div>
            <Definition data={d} />
          </>
        )}
      </QueryState>
      <div className="equal-grid soc-section">
        <Panel
          title="Incident activity"
          subtitle="Created cases and audited closure transitions"
        >
          <QueryState query={incidents}>
            {(d) => (
              <TrendChart
                data={d.data}
                series={[
                  ["created", "Created"],
                  ["resolved", "Resolved transitions"],
                  ["false_positive", "False-positive transitions"],
                ]}
              />
            )}
          </QueryState>
        </Panel>
        <Panel
          title="Risk across case cohorts"
          subtitle="Current scores grouped by creation time"
        >
          <QueryState query={risk}>
            {(d) => (
              <TrendChart
                data={d.data}
                domain={[0, 100]}
                series={[
                  ["average_risk", "Average"],
                  ["maximum_risk", "Maximum"],
                ]}
              />
            )}
          </QueryState>
        </Panel>
      </div>
    </>
  );
}
export function ThreatTrends({ period }) {
  const [draft, setDraft] = useState({}),
    [filters, setFilters] = useState({});
  const events = useAnalyticsQuery("events/trend", period, filters),
    categories = useAnalyticsQuery("categories", period),
    geography = useAnalyticsQuery("geography", period);
  return (
    <>
      <Panel
        title="Security event trends"
        subtitle="Filter observed activity; filters apply to this event chart only."
      >
        <form
          className="analytics-filters"
          onSubmit={(e) => {
            e.preventDefault();
            setFilters(
              Object.fromEntries(
                Object.entries(draft).filter(([, v]) => v.trim()),
              ),
            );
          }}
        >
          {[
            ["event_type", "Event type"],
            ["service", "Service"],
            ["status", "Event status"],
            ["source_ip", "Source IP"],
            ["username", "Username"],
          ].map(([key, label]) => (
            <label key={key}>
              {label}
              <input
                value={draft[key] || ""}
                maxLength={key === "username" ? 255 : 100}
                onChange={(e) => setDraft({ ...draft, [key]: e.target.value })}
              />
            </label>
          ))}
          <button className="button secondary">Apply event filters</button>
          <button
            className="button secondary"
            type="button"
            onClick={() => {
              setDraft({});
              setFilters({});
            }}
          >
            Clear
          </button>
        </form>
        <QueryState query={events}>
          {(d) => (
            <>
              <TrendChart
                data={d.data}
                series={[
                  ["total", "All events"],
                  ["login_failed", "Login failures"],
                  ["access_denied", "Access denied"],
                  ["api_requests", "API requests"],
                  ["sensitive_access", "Sensitive access"],
                ]}
              />
              <div className="analytics-footnote">
                {number(d.total)} events match these filters. Privilege changes:{" "}
                {number(d.data.reduce((n, p) => n + p.privilege_changes, 0))}.
              </div>
              <Definition data={d} />
            </>
          )}
        </QueryState>
      </Panel>
      <div className="equal-grid soc-section">
        <Panel
          title="Threat categories"
          subtitle="Fixed mappings from detection rules"
        >
          <QueryState query={categories}>
            {(d) => (
              <>
                <ComparisonChart
                  data={d.items.map((r) => ({
                    ...r,
                    short: r.category.split(" ")[0],
                  }))}
                  category="short"
                  series={[
                    ["findings", "Findings"],
                    ["incidents", "Cases"],
                  ]}
                />
                <DataTable
                  caption="Threat categories"
                  rowKey="category"
                  rows={d.items}
                  columns={[
                    { key: "category", title: "Category" },
                    { key: "findings", title: "Findings", numeric: true },
                    { key: "incidents", title: "Cases", numeric: true },
                  ]}
                />
                <Definition data={d} />
              </>
            )}
          </QueryState>
        </Panel>
        <Panel
          title="Observed Source Geography"
          subtitle="Supplied evidence metadata; no attribution to countries"
        >
          <QueryState query={geography}>
            {(d) => (
              <>
                <DataTable
                  caption="Observed source geography"
                  rowKey="country"
                  rows={d.items}
                  columns={[
                    { key: "country", title: "Observed country" },
                    { key: "finding_count", title: "Findings", numeric: true },
                    { key: "incident_count", title: "Cases", numeric: true },
                  ]}
                />
                <Definition data={d} />
              </>
            )}
          </QueryState>
        </Panel>
      </div>
    </>
  );
}
export function DetectionPerformance({ period }) {
  const rules = useAnalyticsQuery("detections/rules", period),
    evaluation = useAnalyticsQuery("detections/evaluation", period);
  const [sort, setSort] = useState("findings");
  return (
    <>
      <Panel
        title="Detection rule performance"
        subtitle="Operational volume and analyst closure outcomes; not accuracy."
        action={
          <label className="analytics-sort">
            Sort by
            <select
              aria-label="Sort detection rules"
              value={sort}
              onChange={(e) => setSort(e.target.value)}
            >
              <option value="findings">Findings</option>
              <option value="incidents">Incidents</option>
              <option value="average_risk">Average risk</option>
              <option value="false_positives">False positives</option>
              <option value="rule_id">Rule ID</option>
            </select>
          </label>
        }
      >
        <QueryState query={rules}>
          {(d) => (
            <>
              <ComparisonChart
                data={d.items}
                category="rule_id"
                series={[
                  ["findings", "Findings"],
                  ["incidents", "Cases"],
                  ["false_positives", "False positives"],
                ]}
              />
              <DataTable
                caption="Detection performance"
                rowKey="rule_id"
                rows={[...d.items].sort((a, b) =>
                  sort === "rule_id"
                    ? a.rule_id.localeCompare(b.rule_id)
                    : (b[sort] ?? -1) - (a[sort] ?? -1) ||
                      a.rule_id.localeCompare(b.rule_id),
                )}
                columns={[
                  {
                    key: "rule_id",
                    title: "Rule",
                    render: (r) => (
                      <>
                        <b>{r.rule_id}</b>
                        <div className="muted">{r.name}</div>
                        {!r.enabled && <Badge>Disabled</Badge>}
                      </>
                    ),
                  },
                  ...["findings", "incidents"].map((k) => ({
                    key: k,
                    title: k === "findings" ? "Findings" : "Incidents",
                    numeric: true,
                  })),
                  {
                    key: "average_risk",
                    title: "Avg risk",
                    numeric: true,
                    render: (r) => number(r.average_risk, 1),
                  },
                  {
                    key: "critical_incidents",
                    title: "Critical",
                    numeric: true,
                  },
                  {
                    key: "false_positives",
                    title: "False positives",
                    numeric: true,
                  },
                  {
                    key: "false_positive_rate",
                    title: "FP rate",
                    numeric: true,
                    render: (r) => percent(r.false_positive_rate),
                  },
                  {
                    key: "latest_detection",
                    title: "Latest detection",
                    render: (r) => utc(r.latest_detection),
                  },
                ]}
              />
              <Definition data={d} />
            </>
          )}
        </QueryState>
      </Panel>
      <Panel
        className="soc-section"
        title="Synthetic Evaluation Only"
        subtitle="Development-dataset coverage from retained labelled evidence"
      >
        <QueryState query={evaluation}>
          {(d) => (
            <>
              <div className="analytics-response">
                <Stat
                  label="Expected scenarios"
                  value={number(d.expected_scenarios)}
                />
                <Stat
                  label="Detected / missed"
                  value={`${d.detected_scenarios} / ${d.missed_scenarios}`}
                />
                <Stat
                  label="Scenario recall"
                  value={percent(
                    d.scenario_recall == null ? null : d.scenario_recall * 100,
                  )}
                />
                <Stat
                  label="Unexpected findings"
                  value={number(d.unexpected_findings)}
                />
              </div>
              <p className="analytics-footnote">
                Finding label agreement:{" "}
                {percent(
                  d.finding_label_agreement == null
                    ? null
                    : d.finding_label_agreement * 100,
                )}
                . {d.precision_note}
              </p>
              <Definition data={d} />
            </>
          )}
        </QueryState>
      </Panel>
    </>
  );
}
export function IncidentPerformance({ period }) {
  const backlog = useAnalyticsQuery("incidents/backlog", period),
    trend = useAnalyticsQuery("incidents/trend", period),
    overview = useAnalyticsQuery("overview", period),
    history = useAnalyticsQuery("incidents/status-history", period);
  return (
    <>
      <Panel
        title="Recorded status & backlog over time"
        subtitle="Creation cohort with retained workflow audits"
      >
        <QueryState query={history}>
          {(d) => (
            <>
              <TrendChart
                data={d.data}
                series={[
                  ["open", "Open"],
                  ["investigating", "Investigating"],
                  ["resolved", "Resolved"],
                  ["false_positive", "False positive"],
                  ["unresolved", "Unresolved"],
                ]}
              />
              <p className="analytics-footnote">
                {d.tracked_cases} tracked cases · {d.excluded_cases} excluded
                without creation audit.
              </p>
              <Definition data={d} />
            </>
          )}
        </QueryState>
      </Panel>
      <Panel
        className="soc-section"
        title="Current incident backlog"
        subtitle="Unresolved cases created within the selected period"
      >
        <QueryState query={backlog}>
          {(d) => (
            <>
              <div className="analytics-response">
                <Stat label="Open" value={number(d.open_count)} />
                <Stat
                  label="Investigating"
                  value={number(d.investigating_count)}
                />
                <Stat
                  label="Critical unresolved"
                  value={number(d.critical_unresolved)}
                />
                <Stat
                  label="Average unresolved age"
                  value={duration(d.average_age_seconds)}
                />
              </div>
              <ComparisonChart
                data={d.age_distribution}
                category="label"
                series={[["count", "Unresolved cases"]]}
              />
              {d.oldest && (
                <p className="analytics-footnote">
                  Oldest:{" "}
                  <Link
                    to={`/incidents/${encodeURIComponent(d.oldest.incident_id)}`}
                  >
                    {d.oldest.incident_id}
                  </Link>{" "}
                  · {duration(d.oldest.age_seconds)}
                </p>
              )}
              <Definition data={d} />
            </>
          )}
        </QueryState>
      </Panel>
      <div className="equal-grid soc-section">
        <Panel title="Incident response metrics">
          <QueryState query={overview}>
            {(d) => (
              <>
                <div className="analytics-response">
                  <Stat
                    label="MTTA"
                    value={duration(d.mean_time_to_acknowledge_seconds)}
                    note="Creation → first audited investigation"
                  />
                  <Stat
                    label="MTTR"
                    value={duration(d.mean_time_to_resolve_seconds)}
                    note="Resolved only; creation → resolution"
                  />
                  <Stat
                    label="Resolution rate"
                    value={percent(d.resolution_rate)}
                  />
                  <Stat
                    label="False-positive rate"
                    value={percent(d.false_positive_rate)}
                  />
                </div>
                <Definition data={d} />
              </>
            )}
          </QueryState>
        </Panel>
        <Panel
          title="Lifecycle activity"
          subtitle="Audited transitions; reopening and repeated closures are retained"
        >
          <QueryState query={trend}>
            {(d) => (
              <>
                <TrendChart
                  data={d.data}
                  series={[
                    ["created", "Created"],
                    ["resolved", "Resolved"],
                    ["false_positive", "False positive"],
                    ["reopened", "Reopened"],
                  ]}
                />
                <Definition data={d} />
              </>
            )}
          </QueryState>
        </Panel>
      </div>
    </>
  );
}
export function RiskAnalytics({ period }) {
  const [population, setPopulation] = useState("incidents"),
    [kind, setKind] = useState("username"),
    [recurring, setRecurring] = useState(false);
  const trend = useAnalyticsQuery("risk/trend", period, { population }),
    hist = useAnalyticsQuery("risk/histogram", period, { population }),
    entities = useAnalyticsQuery("entities/high-risk", period, {
      kind,
      recurring_only: kind === "source_ip" && recurring,
      limit: 20,
    });
  return (
    <>
      <div className="analytics-controls">
        <label>
          Risk population
          <select
            value={population}
            onChange={(e) => setPopulation(e.target.value)}
          >
            <option value="incidents">Current incident scores</option>
            <option value="findings">Current finding assessments</option>
          </select>
        </label>
      </div>
      <div className="equal-grid">
        <Panel
          title="Risk cohort profile"
          subtitle="Current scores; not historical score changes"
        >
          <QueryState query={trend}>
            {(d) => (
              <>
                <TrendChart
                  data={d.data}
                  domain={[0, 100]}
                  series={[
                    ["average_risk", "Average"],
                    ["median_risk", "Median"],
                    ["maximum_risk", "Maximum"],
                  ]}
                />
                <Definition data={d} />
              </>
            )}
          </QueryState>
        </Panel>
        <Panel
          title="Risk score histogram"
          subtitle="Mutually exclusive score buckets; 90–100 includes 100"
        >
          <QueryState query={hist}>
            {(d) => (
              <ComparisonChart
                data={d.data}
                category="label"
                series={[["count", "Records"]]}
              />
            )}
          </QueryState>
        </Panel>
      </div>
      <Panel
        className="soc-section"
        title={
          kind === "username"
            ? "High-Risk Associated Accounts"
            : "Risk-associated sources & assets"
        }
        subtitle="Association with a finding does not establish malicious intent."
        action={
          <div className="analytics-controls">
            <label>
              Entity type
              <select value={kind} onChange={(e) => setKind(e.target.value)}>
                <option value="username">Accounts</option>
                <option value="source_ip">Source IPs</option>
                <option value="service">Services</option>
                <option value="device">Devices</option>
              </select>
            </label>
            {kind === "source_ip" && (
              <label className="analytics-check">
                <input
                  type="checkbox"
                  checked={recurring}
                  onChange={(e) => setRecurring(e.target.checked)}
                />
                Recurring sources only
              </label>
            )}
          </div>
        }
      >
        <QueryState query={entities}>
          {(d) => (
            <>
              <DataTable
                caption="High-risk entities"
                rowKey="entity"
                rows={d.items}
                columns={[
                  {
                    key: "entity",
                    title: "Entity",
                    render: (r) => (
                      <>
                        <code>{r.entity}</code>
                        {r.reputation && (
                          <div className="muted">
                            {r.reputation} · {r.intelligence_mode || "no cache"}
                          </div>
                        )}
                        <div className="muted">
                          {r.detection_rules.join(", ")}
                        </div>
                      </>
                    ),
                  },
                  { key: "incident_count", title: "Cases", numeric: true },
                  { key: "finding_count", title: "Findings", numeric: true },
                  { key: "event_count", title: "Events", numeric: true },
                  {
                    key: "suspicious_event_count",
                    title: "Linked events",
                    numeric: true,
                  },
                  {
                    key: "failed_logins",
                    title: "Failed logins",
                    numeric: true,
                  },
                  { key: "access_denials", title: "Denials", numeric: true },
                  {
                    key: "average_risk",
                    title: "Avg case risk",
                    numeric: true,
                    render: (r) => number(r.average_risk, 1),
                  },
                  {
                    key: "highest_risk",
                    title: "Highest risk",
                    render: (r) => <RiskBadge value={r.highest_risk} />,
                  },
                  {
                    key: "latest_activity",
                    title: "Latest activity",
                    render: (r) => utc(r.latest_activity),
                  },
                ]}
              />
              {d.has_more && (
                <p className="analytics-footnote">
                  Showing the top {d.limit} entities.
                </p>
              )}
              <Definition data={d} />
            </>
          )}
        </QueryState>
      </Panel>
    </>
  );
}
export function IntelligenceAnalytics({ period }) {
  const intelligence = useAnalyticsQuery("threat-intelligence", period);
  return (
    <QueryState query={intelligence}>
      {(d) => (
        <>
          <div className="equal-grid">
            {d.modes.map((mode) => (
              <Panel
                key={mode.mode}
                title={
                  mode.simulation
                    ? "Simulated intelligence"
                    : "Live-provider intelligence"
                }
                subtitle="Current cache bundles with their latest check in this period"
                action={
                  <Badge tone={mode.simulation ? "neutral" : "mint"}>
                    {mode.mode.toUpperCase()}
                  </Badge>
                }
              >
                <div className="analytics-response">
                  <Stat
                    label="Indicators checked"
                    value={number(mode.indicators_checked)}
                  />
                  <Stat label="Malicious" value={number(mode.malicious)} />
                  <Stat label="Suspicious" value={number(mode.suspicious)} />
                  <Stat label="Unknown" value={number(mode.unknown)} />
                  <Stat label="Cache hits" value={number(mode.cache_hits)} />
                  <Stat
                    label="Provider failures"
                    value={number(mode.provider_failures)}
                  />
                </div>
                <p className="analytics-footnote">
                  {number(mode.expired)} expired bundles ·{" "}
                  {number(mode.lookups)} recorded lookup requests. Expired
                  evidence is treated as unknown.
                </p>
                <DataTable
                  caption={`${mode.mode} provider coverage`}
                  rowKey="key"
                  rows={mode.provider_usage.map((r) => ({
                    ...r,
                    key: `${r.provider}:${r.lookup_status}`,
                  }))}
                  columns={[
                    { key: "provider", title: "Provider" },
                    { key: "lookup_status", title: "Recorded result" },
                    { key: "bundles", title: "Bundles", numeric: true },
                  ]}
                />
              </Panel>
            ))}
          </div>
          <Definition data={d} />
        </>
      )}
    </QueryState>
  );
}
export function AnalystOperations({ period }) {
  const { user } = useAuth(),
    workload = useAnalyticsQuery(
      "analysts/workload",
      period,
      {},
      user.role === "ADMIN",
    ),
    ai = useAnalyticsQuery("ai/usage", period);
  return (
    <>
      {user.role === "ADMIN" ? (
        <Panel
          title="Analyst workload"
          subtitle="Current assignments, in alphabetical order. Workload visibility only."
        >
          <QueryState query={workload}>
            {(d) => (
              <>
                <DataTable
                  caption="Analyst workload"
                  rowKey="analyst_id"
                  rows={d.items}
                  columns={[
                    { key: "username", title: "Analyst" },
                    ...["assigned", "investigating", "open", "resolved"].map(
                      (k) => ({
                        key: k,
                        title: k[0].toUpperCase() + k.slice(1),
                        numeric: true,
                      }),
                    ),
                    {
                      key: "average_resolution_seconds",
                      title: "Avg resolution time",
                      render: (r) => duration(r.average_resolution_seconds),
                    },
                  ]}
                />
                <p className="analytics-footnote">
                  {d.has_more && `Showing the first ${d.limit} analysts. `}
                  Unassigned: {d.unassigned} · Assigned to inactive/ineligible
                  accounts: {d.assigned_to_ineligible}
                </p>
                <TrendChart
                  data={d.activity}
                  series={[
                    ["assignments", "Assignments"],
                    ["comments", "Comments"],
                    ["status_transitions", "Status transitions"],
                    ["resolutions", "Resolutions"],
                  ]}
                />
                <Definition data={d} />
              </>
            )}
          </QueryState>
        </Panel>
      ) : (
        <div className="info-note">
          Individual analyst workload is restricted to ADMIN. Security analytics
          and aggregate AI usage remain available.
        </div>
      )}
      <Panel
        className="soc-section"
        title="AI Analyst usage"
        subtitle="Recorded requests and saved explanations; no prompts or context exposed"
      >
        <QueryState query={ai}>
          {(d) => (
            <>
              <div className="analytics-response">
                <Stat
                  label="Analyses generated"
                  value={number(d.analyses_generated)}
                />
                <Stat
                  label="Deterministic fallback"
                  value={number(d.fallback_analyses)}
                />
                <Stat
                  label="Provider analyses"
                  value={number(d.provider_analyses)}
                />
                <Stat
                  label="Recorded provider failures"
                  value={number(d.analysis_failures)}
                />
                <Stat label="Cache hits" value={number(d.cache_hits)} />
                <Stat
                  label="Average response"
                  value={
                    d.average_response_ms == null
                      ? "—"
                      : `${number(d.average_response_ms, 1)} ms`
                  }
                />
              </div>
              <p className="analytics-footnote">
                Global stale-analysis count: —. {d.stale_measurement}
              </p>
              <Definition data={d} />
            </>
          )}
        </QueryState>
      </Panel>
    </>
  );
}
