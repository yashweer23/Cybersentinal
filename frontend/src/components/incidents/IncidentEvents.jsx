import { useState } from "react";
import { useIncidentSection } from "../../hooks/useIncident";
import { DataTable, Pagination, Panel, QueryState, Badge } from "../common/UI";
import { label, utc } from "../../utils/format";
import EventDetailDrawer from "./EventDetailDrawer";
const empty = {
  event_type: "",
  source_ip: "",
  username: "",
  service: "",
  status: "",
};
export default function IncidentEvents({ incidentId }) {
  const [draft, setDraft] = useState(empty),
    [filters, setFilters] = useState({}),
    [offset, setOffset] = useState(0),
    [eventId, setEventId] = useState(null);
  const query = useIncidentSection(incidentId, "events", {
    limit: 20,
    offset,
    ...filters,
  });
  return (
    <>
      <Panel
        title="Security event evidence"
        subtitle="Linked records only · exact server-side filters · oldest occurrence first"
      >
        <form
          className="case-event-filters"
          onSubmit={(e) => {
            e.preventDefault();
            setFilters(
              Object.fromEntries(
                Object.entries(draft)
                  .map(([k, v]) => [k, v.trim()])
                  .filter(([, v]) => v),
              ),
            );
            setOffset(0);
          }}
        >
          {Object.keys(empty).map((key) => (
            <label key={key}>
              {label(key)}
              <input
                aria-label={`Event ${label(key).toLowerCase()}`}
                value={draft[key]}
                onChange={(e) => setDraft({ ...draft, [key]: e.target.value })}
                maxLength={
                  key === "username"
                    ? 255
                    : key === "source_ip"
                      ? 45
                      : key === "service"
                        ? 100
                        : key === "status"
                          ? 32
                          : 64
                }
                placeholder={
                  key === "event_type" ? "LOGIN_FAILED" : "Exact value"
                }
              />
            </label>
          ))}
          <div className="case-filter-buttons">
            <button
              className="button secondary small"
              type="button"
              onClick={() => {
                setDraft(empty);
                setFilters({});
                setOffset(0);
              }}
            >
              Reset events
            </button>
            <button className="button small" type="submit">
              Filter events
            </button>
          </div>
        </form>
        <QueryState query={query}>
          {(data) => (
            <>
              <DataTable
                caption="Incident event evidence"
                rowKey="id"
                rows={data.items}
                emptyTitle="No matching event evidence"
                columns={[
                  {
                    key: "event_id",
                    title: "Event",
                    render: (r) => (
                      <button
                        className="text-button mono"
                        onClick={() => setEventId(r.event_id)}
                        aria-label={`View event ${r.event_id}`}
                      >
                        {r.event_id}
                      </button>
                    ),
                  },
                  {
                    key: "timestamp",
                    title: "Timestamp · UTC",
                    render: (r) => utc(r.timestamp),
                  },
                  {
                    key: "event_type",
                    title: "Type",
                    render: (r) => <Badge>{r.event_type}</Badge>,
                  },
                  { key: "source_ip", title: "Source IP" },
                  { key: "destination_ip", title: "Destination IP" },
                  { key: "username", title: "Account" },
                  { key: "service", title: "Service" },
                  { key: "source_port", title: "Source port" },
                  { key: "destination_port", title: "Destination port" },
                  { key: "status", title: "Status" },
                ]}
              />
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
      {eventId && (
        <EventDetailDrawer eventId={eventId} close={() => setEventId(null)} />
      )}
    </>
  );
}
