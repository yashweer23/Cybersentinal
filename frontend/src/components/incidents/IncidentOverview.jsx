import { Panel, SeverityBadge, StatusBadge } from "../common/UI";
import { number, utc } from "../../utils/format";
import RiskBreakdown from "./RiskBreakdown";
import ThreatIntelligencePanel from "./ThreatIntelligencePanel";
export default function IncidentOverview({ incident, openTab }) {
  return (
    <div className="case-overview-grid">
      <Panel
        title="Case at a glance"
        subtitle="Recorded detection and incident metadata"
      >
        <div className="case-content">
          <div className="case-counters">
            <div>
              <strong>{number(incident.confidence)}%</strong>
              <span>Detection confidence</span>
            </div>
            <button onClick={() => openTab("findings")}>
              <strong>{number(incident.findings.total)}</strong>
              <span>Associated findings</span>
            </button>
            <button onClick={() => openTab("events")}>
              <strong>{number(incident.evidence_total)}</strong>
              <span>Retained event references</span>
            </button>
          </div>
          <p>{incident.description}</p>
          <p className="case-small muted">
            Confidence measures how closely activity matches a rule. Related
            events are retained evidence references and may be a bounded sample
            of a finding’s observed activity.
          </p>
        </div>
      </Panel>
      <Panel
        className="case-risk-panel"
        title="Explainable risk"
        subtitle="Highest linked assessment · stored components"
      >
        <RiskBreakdown
          assessment={incident.risk_assessment}
          incidentScore={incident.risk_score}
        />
      </Panel>
      <Panel
        title="Correlated findings"
        subtitle={`Stored relationship decisions · preview of ${Math.min(3, incident.findings.items.length)} of ${number(incident.findings.total)} findings`}
      >
        <div className="case-content">
          {incident.findings.items.slice(0, 3).map((f) => (
            <div className="case-correlation" key={f.finding_id}>
              <div>
                <strong>
                  {f.rule_id} · {f.rule_name}
                </strong>
                <SeverityBadge value={f.severity} />
              </div>
              <p>{f.relationship_reason}</p>
              <span className="mono muted case-small">{f.finding_id}</span>
            </div>
          ))}
          <button className="text-button" onClick={() => openTab("findings")}>
            Inspect all findings and correlation evidence →
          </button>
        </div>
      </Panel>
      <ThreatIntelligencePanel incidentId={incident.incident_id} compact />
      <Panel title="Investigation status">
        <div className="case-content">
          <div className="inline-badges">
            <StatusBadge value={incident.status} />
            <span>
              {incident.assigned_analyst?.full_name ||
                incident.assigned_analyst?.username ||
                "Unassigned"}
            </span>
          </div>
          <p className="case-small muted">
            Last updated {utc(incident.updated_at)}
          </p>
          {incident.resolution_summary && (
            <div className="case-resolution">
              <strong>
                {incident.status === "FALSE_POSITIVE"
                  ? "False-positive reason"
                  : "Resolution summary"}
              </strong>
              <p>{incident.resolution_summary}</p>
              <small>{utc(incident.resolved_at)}</small>
            </div>
          )}
        </div>
      </Panel>
    </div>
  );
}
