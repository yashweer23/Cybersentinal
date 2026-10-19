import { Link } from "react-router-dom";
import {
  Badge,
  DataTable,
  RiskBadge,
  SeverityBadge,
  StatusBadge,
  Time,
} from "../common/UI";
import { label, number } from "../../utils/format";
export function IncidentTable({ rows, returnTo }) {
  return (
    <DataTable
      rows={rows}
      rowKey="incident_id"
      caption="Incidents"
      columns={[
        {
          key: "incident_id",
          title: "Incident",
          render: (r) => (
            <Link
              className="incident-link"
              to={`/incidents/${encodeURIComponent(r.incident_id)}${returnTo ? `?returnTo=${encodeURIComponent(returnTo)}` : ""}`}
            >
              <span className="mono">{r.incident_id}</span>
              <strong>{r.title}</strong>
            </Link>
          ),
        },
        {
          key: "severity",
          title: "Severity",
          render: (r) => <SeverityBadge value={r.severity} />,
        },
        {
          key: "risk_score",
          title: "Risk",
          render: (r) => <RiskBadge value={r.risk_score} />,
        },
        {
          key: "source_ip",
          title: "Source IP",
          render: (r) => <span className="mono">{r.source_ip || "—"}</span>,
        },
        { key: "username", title: "Account" },
        {
          key: "status",
          title: "Status",
          render: (r) => <StatusBadge value={r.status} />,
        },
        {
          key: "assigned_analyst",
          title: "Analyst",
          render: (r) =>
            r.assigned_analyst?.full_name ||
            r.assigned_analyst?.username || (
              <span className="muted">Unassigned</span>
            ),
        },
        {
          key: "detected_at",
          title: "Detected · UTC",
          render: (r) => <Time value={r.detected_at} />,
        },
      ]}
    />
  );
}
export function EventTable({ rows, live = false }) {
  const columns = [
    {
      key: "timestamp",
      title: "Time · UTC",
      render: (r) => <Time value={r.timestamp} />,
    },
    {
      key: "event_type",
      title: "Event type",
      render: (r) => (
        <span
          className={`event-label ${["LOGIN_FAILED", "ACCESS_DENIED", "MALWARE_ALERT"].includes(r.event_type) ? "event-alert" : ""}`}
        >
          <i />
          {label(r.event_type)}
        </span>
      ),
    },
    {
      key: "source_ip",
      title: "Source IP",
      render: (r) => <span className="mono">{r.source_ip}</span>,
    },
    ...(live
      ? [
          {
            key: "destination_ip",
            title: "Destination IP",
            render: (r) => (
              <span className="mono">{r.destination_ip || "—"}</span>
            ),
          },
        ]
      : []),
    { key: "username", title: "Account" },
    { key: "service", title: "Service" },
    {
      key: "status",
      title: "Status",
      render: (r) => (
        <Badge
          tone={
            ["failed", "denied"].includes(r.status.toLowerCase())
              ? "high"
              : "neutral"
          }
        >
          {label(r.status)}
        </Badge>
      ),
    },
    ...(live
      ? [
          {
            key: "processed",
            title: "Evaluated",
            render: (r) => (
              <span className={r.processed ? "green-text" : "muted"}>
                {r.processed ? "Yes" : "Pending"}
              </span>
            ),
          },
        ]
      : []),
  ];
  return (
    <DataTable
      rows={rows}
      rowKey="id"
      caption="Security events"
      columns={columns}
      emptyTitle="No security events to display"
      emptyDescription={
        live
          ? "Newly ingested events appear here while live updates are enabled."
          : "No events occurred within this time range."
      }
    />
  );
}
export function TopIPTable({ rows }) {
  return (
    <DataTable
      rows={rows}
      rowKey="ip"
      caption="Top suspicious IPs"
      columns={[
        {
          key: "ip",
          title: "Source",
          render: (r) => (
            <div className="cell-stack">
              <Link
                className="mono"
                to={`/threat-intelligence?ip=${encodeURIComponent(r.ip)}`}
              >
                {r.ip}
              </Link>
              {r.simulation && <Badge tone="simulation">Simulated</Badge>}
            </div>
          ),
        },
        {
          key: "reputation_level",
          title: "Reputation",
          render: (r) => (
            <div className="cell-stack">
              <span>{label(r.reputation_level)}</span>
              <small className="muted">{label(r.intelligence_status)}</small>
            </div>
          ),
        },
        {
          key: "finding_count",
          title: "Findings",
          numeric: true,
          render: (r) => number(r.finding_count),
        },
        {
          key: "incident_count",
          title: "Cases",
          numeric: true,
          render: (r) => number(r.incident_count),
        },
        {
          key: "highest_risk_score",
          title: "Case risk",
          render: (r) => <RiskBadge value={r.highest_risk_score} />,
        },
        {
          key: "latest_activity",
          title: "Latest · UTC",
          render: (r) => <Time value={r.latest_activity} />,
        },
      ]}
    />
  );
}
export function TargetedTable({ rows }) {
  return (
    <DataTable
      rows={rows}
      rowKey="username"
      caption="Most targeted accounts"
      columns={[
        {
          key: "username",
          title: "Account",
          render: (r) => <span className="mono">{r.username}</span>,
        },
        ...[
          ["failed_logins", "Failures"],
          ["access_denials", "Denials"],
          ["finding_count", "Findings"],
          ["incident_count", "Cases"],
        ].map(([key, title]) => ({
          key,
          title,
          numeric: true,
          render: (r) => number(r[key]),
        })),
      ]}
    />
  );
}
