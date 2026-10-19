import { useState } from "react";
import {
  Activity,
  Crosshair,
  Gauge,
  MessageSquare,
  ClipboardList,
} from "lucide-react";
import { useIncidentSection } from "../../hooks/useIncident";
import { Badge, EmptyState, Pagination, Panel, QueryState } from "../common/UI";
import { label, utc } from "../../utils/format";
import { EvidenceFields } from "./EvidenceFields";
const kinds = {
  SECURITY_EVENT: [Activity, "Security event"],
  DETECTION: [Crosshair, "Detection finding"],
  RISK_ASSESSMENT: [Gauge, "Risk assessment"],
  COMMENT: [MessageSquare, "Analyst note"],
  AUDIT: [ClipboardList, "Case activity"],
};
export default function IncidentTimeline({ incidentId }) {
  const [order, setOrder] = useState("asc"),
    [offset, setOffset] = useState(0);
  const query = useIncidentSection(incidentId, "timeline", {
    limit: 20,
    offset,
    order,
  });
  return (
    <Panel
      title="Investigation timeline"
      subtitle="Event occurrence and recorded analyst activity · all timestamps UTC"
      action={
        <label className="case-inline-label">
          Order
          <select
            aria-label="Timeline order"
            value={order}
            onChange={(e) => {
              setOrder(e.target.value);
              setOffset(0);
            }}
          >
            <option value="asc">Oldest first</option>
            <option value="desc">Newest first</option>
          </select>
        </label>
      }
    >
      <QueryState query={query}>
        {(data) => (
          <>
            {!data.items.length && (
              <EmptyState
                title="No timeline activity"
                description="No entries have been recorded for this case."
              />
            )}
            <ol className="case-timeline">
              {data.items.map((item) => {
                const [Icon, kind] = kinds[item.type] || [
                  Activity,
                  label(item.type),
                ];
                const details = Object.fromEntries(
                  Object.entries(item.details).filter(([, v]) => v != null),
                );
                return (
                  <li
                    key={`${item.type}:${item.reference_id}`}
                    className={`timeline-${item.type.toLowerCase()}`}
                  >
                    <div className="case-timeline-icon">
                      <Icon size={16} />
                    </div>
                    <div className="case-timeline-body">
                      <div className="case-timeline-meta">
                        <Badge>{kind}</Badge>
                        <time dateTime={item.timestamp}>
                          {utc(item.timestamp)}
                        </time>
                      </div>
                      <h3>
                        {item.type === "AUDIT" ? label(item.title) : item.title}
                      </h3>
                      {item.actor_username && (
                        <p className="case-small">
                          By <strong>{item.actor_username}</strong>
                        </p>
                      )}
                      <span className="case-small muted mono">
                        {item.reference_id}
                      </span>
                      {Object.keys(details).length > 0 && (
                        <EvidenceFields data={details} />
                      )}
                    </div>
                  </li>
                );
              })}
            </ol>
            <Pagination
              offset={offset}
              limit={20}
              total={data.total}
              onChange={setOffset}
            />
          </>
        )}
      </QueryState>
    </Panel>
  );
}
