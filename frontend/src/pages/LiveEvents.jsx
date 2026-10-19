import { useMemo, useState } from "react";
import { Pause, Play, RefreshCw, Trash2 } from "lucide-react";
import { useLiveEvents } from "../hooks/useLiveEvents";
import {
  Badge,
  EmptyState,
  ErrorState,
  LoadingSkeleton,
  PageHeading,
  Panel,
  Time,
} from "../components/common/UI";
import { EventTable } from "../components/dashboard/Tables";
import { label, number } from "../utils/format";
export default function LiveEvents() {
  const feed = useLiveEvents();
  const [filters, setFilters] = useState({
    event_type: "",
    username: "",
    source_ip: "",
    status: "",
  });
  const rows = useMemo(
    () =>
      feed.rows.filter((row) =>
        Object.entries(filters).every(
          ([key, value]) =>
            !value ||
            String(row[key] || "")
              .toLowerCase()
              .includes(value.toLowerCase()),
        ),
      ),
    [feed.rows, filters],
  );
  const types = useMemo(
    () => [...new Set(feed.rows.map((r) => r.event_type))].sort(),
    [feed.rows],
  );
  return (
    <>
      <PageHeading
        title="Live security events"
        description="Newly ingested logs, ordered by arrival. Polls every 5 seconds while visible."
      >
        <Badge tone={feed.live ? "low" : "neutral"}>
          {feed.live ? "Live updates" : "Updates paused"}
        </Badge>
        <button className="button secondary small" onClick={feed.toggle}>
          {feed.live ? <Pause size={14} /> : <Play size={14} />}{" "}
          {feed.live ? "Pause" : "Resume"}
        </button>
        <button
          className="icon-button"
          aria-label="Refresh live events"
          onClick={feed.retry}
        >
          <RefreshCw size={17} />
        </button>
      </PageHeading>
      <div className="filter-panel">
        <div className="filter-grid live-filters">
          <label>
            Event type
            <select
              aria-label="Event type"
              value={filters.event_type}
              onChange={(e) =>
                setFilters({ ...filters, event_type: e.target.value })
              }
            >
              <option value="">All events</option>
              {types.map((t) => (
                <option key={t} value={t}>
                  {label(t)}
                </option>
              ))}
            </select>
          </label>
          {[
            ["username", "Account"],
            ["source_ip", "Source IP"],
            ["status", "Status"],
          ].map(([key, title]) => (
            <label key={key}>
              {title}
              <input
                value={filters[key]}
                placeholder={`Filter ${title.toLowerCase()}`}
                onChange={(e) =>
                  setFilters({ ...filters, [key]: e.target.value })
                }
              />
            </label>
          ))}
        </div>
        <p className="filter-note">
          Filters apply to the retained feed only · maximum 500 rows · initial
          snapshot covers the last 24 hours.
        </p>
      </div>
      <Panel
        title="Event stream"
        subtitle={`${number(rows.length)} visible / ${number(feed.rows.length)} retained`}
        action={
          <button className="button secondary small" onClick={feed.clear}>
            <Trash2 size={14} />
            Clear display
          </button>
        }
      >
        {feed.error && (
          <ErrorState
            error={feed.error}
            retry={feed.retry}
            stale={feed.rows.length > 0}
          />
        )}
        {feed.loading ? (
          <LoadingSkeleton rows={7} />
        ) : rows.length ? (
          <EventTable rows={rows} live />
        ) : (
          <EmptyState
            title="No events in this view"
            description="Adjust the local filters or wait for newly ingested events. Clearing the display never deletes logs."
          />
        )}
        <div className="panel-footnote">
          Last successful fetch: <Time value={feed.updatedAt} /> · Stored event
          timestamps may be earlier than arrival.
        </div>
      </Panel>
    </>
  );
}
