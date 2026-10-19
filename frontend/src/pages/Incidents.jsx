import { useEffect, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { Filter, RotateCcw } from "lucide-react";
import { useDashboard } from "../context/DashboardContext";
import { polling } from "../hooks/useDashboardQuery";
import { listIncidents } from "../services/incidentsApi";
import {
  PageHeading,
  Panel,
  Pagination,
  QueryState,
} from "../components/common/UI";
import { IncidentTable } from "../components/dashboard/Tables";
import { label } from "../utils/format";
const empty = {
  status: "",
  severity: "",
  minimum_risk: "",
  assigned_analyst: "",
  username: "",
  source_ip: "",
  start_time: "",
  end_time: "",
};
export function incidentParams(filters, offset) {
  const params = { limit: 20, offset };
  for (const [key, value] of Object.entries(filters))
    if (value !== "")
      params[key] = key.endsWith("_time") ? `${value}:00Z` : value;
  return params;
}
export default function Incidents() {
  const { preferences } = useDashboard();
  const [search, setSearch] = useSearchParams();
  const filters = Object.fromEntries(
    Object.keys(empty).map((key) => [key, search.get(key) || ""]),
  );
  const rawOffset = Number(search.get("offset") || 0);
  const offset =
    Number.isInteger(rawOffset) && rawOffset >= 0 && rawOffset <= 1000000
      ? rawOffset
      : 0;
  const [draft, setDraft] = useState(filters),
    [dateError, setDateError] = useState("");
  useEffect(() => {
    setDraft(
      Object.fromEntries(
        Object.keys(empty).map((key) => [key, search.get(key) || ""]),
      ),
    );
  }, [search]);
  const setOffset = (value) => {
    const next = new URLSearchParams(search);
    next.set("offset", String(value));
    setSearch(next);
  };
  const params = incidentParams(filters, offset);
  const query = useQuery({
    queryKey: ["incidents", params],
    queryFn: ({ signal }) => listIncidents(params, signal),
    refetchInterval: polling(preferences, 10000),
  });
  const update = (e) => setDraft({ ...draft, [e.target.name]: e.target.value });
  const apply = (e) => {
    e.preventDefault();
    if (
      draft.start_time &&
      draft.end_time &&
      draft.start_time > draft.end_time
    ) {
      setDateError("The start time must precede the end time.");
      return;
    }
    setDateError("");
    setSearch(
      Object.fromEntries(
        Object.entries(draft).filter(([, value]) => value !== ""),
      ),
    );
  };
  return (
    <>
      <PageHeading
        title="Incident queue"
        description="Prioritize security cases by severity, risk and ownership."
      />
      <form className="filter-panel" onSubmit={apply}>
        <div className="filter-title">
          <Filter size={16} />
          <strong>Filter incidents</strong>
          <span>Server-side · 20 cases per page</span>
        </div>
        <div className="filter-grid">
          <label>
            Status
            <select
              aria-label="Status"
              name="status"
              value={draft.status}
              onChange={update}
            >
              <option value="">All statuses</option>
              {["OPEN", "INVESTIGATING", "RESOLVED", "FALSE_POSITIVE"].map(
                (v) => (
                  <option key={v}>{v}</option>
                ),
              )}
            </select>
          </label>
          <label>
            Severity
            <select
              aria-label="Severity"
              name="severity"
              value={draft.severity}
              onChange={update}
            >
              <option value="">All severities</option>
              {["CRITICAL", "HIGH", "MEDIUM", "LOW"].map((v) => (
                <option key={v} value={v}>
                  {label(v)}
                </option>
              ))}
            </select>
          </label>
          <label>
            Minimum risk
            <input
              type="number"
              min="0"
              max="100"
              step="1"
              name="minimum_risk"
              value={draft.minimum_risk}
              onChange={update}
              placeholder="0–100"
            />
          </label>
          <label>
            Account
            <input
              name="username"
              value={draft.username}
              onChange={update}
              placeholder="Exact username"
              maxLength={100}
            />
          </label>
          <label>
            Source IP
            <input
              name="source_ip"
              value={draft.source_ip}
              onChange={update}
              placeholder="IPv4 or IPv6"
              maxLength={45}
            />
          </label>
          <label>
            Assigned analyst ID
            <input
              name="assigned_analyst"
              value={draft.assigned_analyst}
              onChange={update}
              placeholder="Analyst UUID"
              pattern="[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
            />
          </label>
          <label>
            Evidence from · UTC
            <input
              type="datetime-local"
              name="start_time"
              value={draft.start_time}
              onChange={update}
            />
          </label>
          <label>
            Evidence to · UTC
            <input
              type="datetime-local"
              name="end_time"
              value={draft.end_time}
              onChange={update}
            />
          </label>
        </div>
        {dateError && (
          <p role="alert" className="text-critical">
            {dateError}
          </p>
        )}
        <div className="filter-actions">
          <span>Date filters match case evidence overlap.</span>
          <button
            type="button"
            className="button secondary small"
            onClick={() => {
              setDraft(empty);
              setSearch({});
              setDateError("");
            }}
          >
            <RotateCcw size={14} />
            Reset
          </button>
          <button className="button small" type="submit">
            Apply filters
          </button>
        </div>
      </form>
      <Panel
        title="Security cases"
        subtitle="Ordered by severity, risk and newest creation time"
      >
        <QueryState query={query}>
          {(d) => (
            <>
              <IncidentTable
                rows={d.items}
                returnTo={`/incidents${search.size ? `?${search}` : ""}`}
              />
              <Pagination
                offset={offset}
                limit={20}
                total={d.total}
                onChange={setOffset}
              />
            </>
          )}
        </QueryState>
      </Panel>
    </>
  );
}
