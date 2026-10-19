import {
  Activity,
  Crosshair,
  FileSearch,
  Globe2,
  Gauge,
  ShieldAlert,
} from "lucide-react";
import { useDashboardQuery } from "../hooks/useDashboardQuery";
import { useDashboard } from "../context/DashboardContext";
import {
  Badge,
  MetricCard,
  PageHeading,
  Panel,
  PanelLink,
  QueryState,
  Time,
} from "../components/common/UI";
import {
  SecurityTimeline,
  SeverityChart,
  DistributionBars,
} from "../components/dashboard/Charts";
import {
  IncidentTable,
  EventTable,
  TopIPTable,
  TargetedTable,
} from "../components/dashboard/Tables";
import { number } from "../utils/format";
export default function Overview() {
  const { range, preferences } = useDashboard();
  const summary = useDashboardQuery("overview", { interval: 10000 });
  const timeline = useDashboardQuery("events/timeline");
  const severity = useDashboardQuery("incidents/severity");
  const risk = useDashboardQuery("risk/distribution");
  const incidents = useDashboardQuery("incidents/recent", {
    interval: 10000,
    params: { limit: 5 },
  });
  const ips = useDashboardQuery("threats/top-ips", { params: { limit: 5 } });
  const users = useDashboardQuery("users/targeted", { params: { limit: 5 } });
  const events = useDashboardQuery("events/recent", {
    interval: 10000,
    params: { limit: 7 },
  });
  return (
    <>
      <PageHeading
        eyebrow="MONITOR / ANALYZE / RESPOND"
        title="Security overview"
        description="A clear view of your security posture and the activity that needs attention."
      >
        <Badge tone={preferences.autoRefresh ? "low" : "neutral"}>
          {preferences.autoRefresh ? "Auto refresh on" : "Auto refresh paused"}
        </Badge>
      </PageHeading>
      <QueryState query={summary}>
        {(d) => (
          <>
            <div className="metrics-grid">
              <MetricCard
                label="Active incidents"
                value={d.active_incidents}
                icon={Crosshair}
                subtitle="Open & investigating"
              />
              <MetricCard
                label="Critical incidents"
                value={d.critical_incidents}
                icon={ShieldAlert}
                subtitle="Critical severity · all states"
                tone="critical"
              />
              <MetricCard
                label="Security events"
                value={d.events_in_range}
                icon={Activity}
                subtitle={`Observed in the last ${range.toUpperCase()}`}
              />
              <MetricCard
                label="Detection findings"
                value={d.total_findings}
                icon={FileSearch}
                subtitle="Behavioral rule matches"
              />
              <MetricCard
                label="Suspicious IPs"
                value={d.suspicious_ips}
                icon={Globe2}
                subtitle="Sources linked to findings / cases"
              />
              <MetricCard
                label="Average risk"
                value={d.average_risk_score}
                icon={Gauge}
                subtitle="Current incident scores / 100"
                tone="high"
              />
            </div>
            <div className="scope-note">
              <span>
                <i className="tiny-dot" />
                Selected period · {range.toUpperCase()} · UTC
              </span>
              <span>
                {number(d.unprocessed_events)} events awaiting detection{" "}
                <span className="muted">· global backlog</span>
              </span>
            </div>
          </>
        )}
      </QueryState>
      <div className="overview-charts">
        <Panel
          title="Security activity"
          subtitle="Event occurrence over time"
          action={<Badge>LAST {range.toUpperCase()}</Badge>}
        >
          <QueryState query={timeline}>
            {(d) => <SecurityTimeline data={d} />}
          </QueryState>
        </Panel>
        <Panel
          title="Incident severity"
          subtitle="Current case severity in selected period"
        >
          <QueryState query={severity}>
            {(d) => <SeverityChart data={d} />}
          </QueryState>
        </Panel>
      </div>
      <div className="soc-section">
        <Panel
          title="Recent incidents"
          subtitle="Newest cases requiring context and review"
          action={<PanelLink to="/incidents">View incident queue</PanelLink>}
        >
          <QueryState query={incidents}>
            {(d) => <IncidentTable rows={d.items} />}
          </QueryState>
        </Panel>
      </div>
      <div className="secondary-grid">
        <Panel
          title="Risk distribution"
          subtitle="Current incident risk categories · 0–100"
        >
          <QueryState query={risk}>
            {(d) => <DistributionBars data={d} colors />}
          </QueryState>
          <div className="panel-footnote">
            Low 0–24 · Medium 25–49 · High 50–74 · Critical 75–100
          </div>
        </Panel>
        <Panel
          title="Most targeted accounts"
          subtitle="Observed suspicious activity · not confirmed compromise"
        >
          <QueryState query={users}>
            {(d) => <TargetedTable rows={d.items} />}
          </QueryState>
        </Panel>
      </div>
      <div className="soc-section">
        <Panel
          title="Top suspicious IPs"
          subtitle="Ranked by associated incident risk, case counts and findings"
          action={
            <PanelLink to="/threat-intelligence">Threat intelligence</PanelLink>
          }
        >
          <QueryState query={ips}>
            {(d) => <TopIPTable rows={d.items} />}
          </QueryState>
        </Panel>
      </div>
      <div className="soc-section">
        <Panel
          title="Recent security events"
          subtitle="Latest observed activity in the selected time range"
          action={<PanelLink to="/events">Open live feed</PanelLink>}
        >
          <QueryState query={events}>
            {(d) => <EventTable rows={d.items} />}
          </QueryState>
        </Panel>
      </div>
      {summary.data && (
        <div className="scope-note">
          <span>
            Metrics assembled <Time value={summary.data.scope?.as_of} />
          </span>
          <span>
            Incident metrics use case detection time; events use occurrence
            time.
          </span>
        </div>
      )}
    </>
  );
}
