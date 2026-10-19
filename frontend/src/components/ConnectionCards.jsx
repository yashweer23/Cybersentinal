import { Monitor, Server, Database, ArrowUpRight } from "lucide-react";
import StatusBadge from "./StatusBadge";

export default function ConnectionCards({ health }) {
  const db = health.data?.services.database;
  const apiConnected = Boolean(health.data);
  const unknown = !health.data && !health.error;
  const cards = [
    {
      title: "Frontend runtime",
      icon: Monitor,
      value: "Running",
      tone: "success",
      description: "React application rendered in your browser",
      label: "React + Vite",
      detail: "Browser ready",
    },
    {
      title: "Backend API",
      icon: Server,
      value: apiConnected ? "Connected" : unknown ? "Checking" : "Unavailable",
      tone: apiConnected ? "success" : unknown ? "neutral" : "warning",
      description: "FastAPI REST service and API documentation",
      label: "FastAPI",
      detail: apiConnected ? "API responding" : "Awaiting response",
    },
    {
      title: "Database",
      icon: Database,
      value:
        db?.status === "connected"
          ? "Connected"
          : db
            ? "Unavailable"
            : unknown
              ? "Checking"
              : "Unknown",
      tone:
        db?.status === "connected"
          ? "success"
          : unknown
            ? "neutral"
            : "warning",
      description: "PostgreSQL connection verified with SELECT 1",
      label: "PostgreSQL",
      detail:
        db?.latency_ms != null
          ? `${db.latency_ms.toFixed(1)} ms query`
          : "Awaiting query",
    },
  ];
  return (
    <section className="connection-grid" aria-label="Connection status">
      {cards.map(
        ({ title, icon: Icon, value, tone, description, label, detail }) => (
          <article className="connection-card" key={title}>
            <div className="card-top">
              <span className="component-icon">
                <Icon size={20} />
              </span>
              <span>{title}</span>
              <ArrowUpRight size={15} className="muted" />
            </div>
            <h2>{value}</h2>
            <p>{description}</p>
            <div className="card-bottom">
              <span>{label}</span>
              <StatusBadge tone={tone}>{detail}</StatusBadge>
            </div>
          </article>
        ),
      )}
    </section>
  );
}
