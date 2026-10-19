import {
  Bot,
  ArrowLeft,
  MessageSquarePlus,
  RefreshCw,
  UserRoundPlus,
} from "lucide-react";
import { Link } from "react-router-dom";
import { RiskBadge, SeverityBadge, StatusBadge } from "../common/UI";
import { utc } from "../../utils/format";
import { statusAction } from "./StatusControl";
export default function IncidentHeader({
  incident,
  canWrite,
  backTo,
  busy,
  onAnalyze,
  onAssign,
  onStatus,
  onNote,
  refresh,
}) {
  return (
    <header className="case-header">
      <Link to={backTo} className="panel-link">
        <ArrowLeft size={14} />
        Back to incident queue
      </Link>
      <div className="case-heading">
        <div>
          <div className="case-id-row">
            <span className="mono">{incident.incident_id}</span>
            <SeverityBadge value={incident.severity} />
            <RiskBadge value={incident.risk_score} />
          </div>
          <h1>{incident.title}</h1>
        </div>
        <StatusBadge value={incident.status} />
      </div>
      <p className="case-description">{incident.description}</p>
      <dl className="case-header-meta">
        <div>
          <dt>Assigned analyst</dt>
          <dd>{incident.assigned_analyst?.username || "Unassigned"}</dd>
        </div>
        <div>
          <dt>Source IP</dt>
          <dd className="mono">{incident.source_ip || "Not recorded"}</dd>
        </div>
        <div>
          <dt>Account</dt>
          <dd>{incident.username || "Not recorded"}</dd>
        </div>
        <div>
          <dt>First seen</dt>
          <dd>{utc(incident.first_seen)}</dd>
        </div>
        <div>
          <dt>Last seen</dt>
          <dd>{utc(incident.last_seen)}</dd>
        </div>
        <div>
          <dt>Detected</dt>
          <dd>{utc(incident.detected_at)}</dd>
        </div>
      </dl>
      <div className="case-actions">
        <button className="button secondary small" onClick={onAnalyze}>
          <Bot size={15} />
          {canWrite ? "Analyze with AI" : "View analysis"}
        </button>
        {canWrite ? (
          <>
            <button className="button secondary small" onClick={onAssign}>
              <UserRoundPlus size={15} />
              Assign
            </button>
            {incident.allowed_transitions.map((status) => (
              <button
                className={`button ${status === "FALSE_POSITIVE" ? "secondary" : ""} small`}
                key={status}
                onClick={() => onStatus(status)}
              >
                {statusAction(status, incident.status)}
              </button>
            ))}
            <button className="button secondary small" onClick={onNote}>
              <MessageSquarePlus size={15} />
              Add note
            </button>
          </>
        ) : (
          <span className="case-small muted">
            Viewer access · read-only investigation
          </span>
        )}
        <button
          className="button secondary small case-refresh"
          disabled={busy}
          onClick={refresh}
        >
          <RefreshCw size={15} />
          {busy ? "Refreshing…" : "Refresh case"}
        </button>
      </div>
    </header>
  );
}
