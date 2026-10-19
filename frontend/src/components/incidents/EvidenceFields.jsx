import { label, number } from "../../utils/format";
const names = {
  attempt_count: "Failed attempts",
  threshold: "Detection threshold",
  window_seconds: "Window (seconds)",
  duration_seconds: "Observed duration (seconds)",
  unique_username_count: "Accounts targeted",
  required_speed_kmh: "Required speed (km/h)",
  distance_km: "Distance (km)",
  event_count: "Events observed",
};
function valueText(value) {
  if (value == null) return "Not recorded";
  if (typeof value === "boolean") return value ? "Yes" : "No";
  if (typeof value === "number") return number(value, 3);
  if (typeof value === "string") return value;
  if (Array.isArray(value)) return value.map(valueText).join(", ");
  return Object.entries(value)
    .map(([k, v]) => `${label(k)}: ${valueText(v)}`)
    .join(" · ");
}
export function EvidenceFields({ data, omit = [] }) {
  const entries = Object.entries(data || {}).filter(
    ([key]) => !omit.includes(key),
  );
  return (
    <dl className="case-facts">
      {entries.map(([key, value]) => (
        <div key={key}>
          <dt>{names[key] || label(key)}</dt>
          <dd>{valueText(value)}</dd>
        </div>
      ))}
    </dl>
  );
}
export function RawData({ title = "Raw evidence", value }) {
  return (
    <details className="case-raw">
      <summary>{title}</summary>
      <pre tabIndex={0} aria-label={title}>
        {JSON.stringify(value, null, 2)}
      </pre>
    </details>
  );
}
