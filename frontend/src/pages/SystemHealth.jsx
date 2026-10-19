import {
  Activity,
  Bot,
  Database,
  Globe2,
  Server,
  Workflow,
} from "lucide-react";
import { useDashboardQuery } from "../hooks/useDashboardQuery";
import {
  Badge,
  PageHeading,
  Panel,
  QueryState,
  Time,
} from "../components/common/UI";
import { label, number } from "../utils/format";
export default function SystemHealth() {
  const query = useDashboardQuery("system/health", {
    scoped: false,
    interval: 30000,
  });
  return (
    <>
      <PageHeading
        title="System health"
        description="Database-backed readiness and processing status. Refreshes every 30 seconds."
      />
      <QueryState query={query} strict>
        {(d) => (
          <>
            <div className="health-grid">
              {[
                [
                  Server,
                  "FastAPI",
                  label(d.api),
                  "Authenticated API response",
                  "low",
                ],
                [
                  Database,
                  "PostgreSQL",
                  label(d.database),
                  "Database connection verified",
                  "low",
                ],
                [
                  Workflow,
                  "Detection engine",
                  label(d.detection_engine.status),
                  "Processing is triggered on demand",
                  "low",
                ],
                [
                  Globe2,
                  "Threat intelligence",
                  d.threat_intelligence.enabled
                    ? d.threat_intelligence.simulation
                      ? "Simulated mode"
                      : "Live mode"
                    : "Disabled",
                  "Provider configuration; not an external availability probe",
                  d.threat_intelligence.simulation ? "simulation" : "neutral",
                ],
                [
                  Activity,
                  "Event processing",
                  `${number(d.detection_engine.unprocessed_events)} pending`,
                  "Stored evaluation backlog",
                  d.detection_engine.unprocessed_events ? "high" : "low",
                ],
                [
                  Bot,
                  "AI analyst",
                  label(d.ai_analyst.status),
                  d.ai_analyst.note,
                  "neutral",
                ],
              ].map(([Icon, title, status, description, tone]) => (
                <section className="health-card" key={title}>
                  <div>
                    <span className="health-icon">
                      <Icon size={21} />
                    </span>
                    <Badge tone={tone}>{status}</Badge>
                  </div>
                  <h2>{title}</h2>
                  <p>{description}</p>
                </section>
              ))}
            </div>
            <Panel
              title="Processing metrics"
              subtitle="Global database totals · independent of dashboard time range"
            >
              <dl className="detail-grid operational-metrics">
                <div>
                  <dt>Events stored</dt>
                  <dd>{number(d.total_events)}</dd>
                </div>
                <div>
                  <dt>Events evaluated</dt>
                  <dd>{number(d.detection_engine.events_processed)}</dd>
                </div>
                <div>
                  <dt>Events pending</dt>
                  <dd>{number(d.detection_engine.unprocessed_events)}</dd>
                </div>
                <div>
                  <dt>Latest event · UTC</dt>
                  <dd>
                    <Time value={d.latest_event_timestamp} />
                  </dd>
                </div>
                <div>
                  <dt>Last detection run · UTC</dt>
                  <dd>
                    <Time value={d.detection_engine.last_processing_time} />
                  </dd>
                </div>
                <div>
                  <dt>Last run duration</dt>
                  <dd>
                    {number(d.detection_engine.last_processing_duration_ms, 1)}{" "}
                    ms
                  </dd>
                </div>
              </dl>
              <div className="panel-footnote">
                Successful observation: <Time value={d.as_of} />
              </div>
            </Panel>
          </>
        )}
      </QueryState>
    </>
  );
}
