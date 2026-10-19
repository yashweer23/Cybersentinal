// Validate the fields we render. A broken contract must not silently become a zero metric.
export class ContractError extends Error {
  constructor() {
    super(
      "The API returned an unexpected response. Refresh or check the backend version.",
    );
    this.name = "ContractError";
  }
}
export function assert(condition) {
  if (!condition) throw new ContractError();
}
export const object = (value) =>
  value !== null && typeof value === "object" && !Array.isArray(value);
export function fields(value, specification) {
  assert(object(value));
  for (const [key, type] of Object.entries(specification)) {
    const nullable = type.endsWith("?");
    const expected = type.replace("?", "");
    if (nullable && value[key] === null) continue;
    assert(
      expected === "array"
        ? Array.isArray(value[key])
        : expected === "object"
          ? object(value[key])
          : typeof value[key] === expected,
    );
    if (expected === "number") assert(Number.isFinite(value[key]));
    if (expected === "string" && /(_at|timestamp|_time)$/.test(key))
      assert(Number.isFinite(Date.parse(value[key])));
    if (key === "assigned_analyst" && value[key] !== null)
      fields(value[key], { username: "string", full_name: "string?" });
  }
  return value;
}
export function rows(value, key, specification) {
  fields(value, { [key]: "array" });
  value[key].forEach((row) => fields(row, specification));
  return value;
}
export const eventFields = {
  id: "string",
  event_id: "string",
  ingestion_sequence: "string",
  timestamp: "string",
  event_type: "string",
  source_ip: "string",
  destination_ip: "string?",
  username: "string?",
  service: "string?",
  status: "string",
  processed: "boolean",
};
export const incidentFields = {
  incident_id: "string",
  title: "string",
  severity: "string",
  risk_score: "number",
  status: "string",
  source_ip: "string?",
  username: "string?",
  assigned_analyst: "object?",
  detected_at: "string",
};
export function cursor(value) {
  assert(typeof value === "string" && /^\d+$/.test(value));
  return value;
}
export function eventRows(value) {
  rows(value, "items", eventFields);
  value.items.forEach((row) => {
    cursor(row.ingestion_sequence);
    assert(Number.isFinite(Date.parse(row.timestamp)));
  });
  return value;
}
export function providers(value) {
  fields(value, {
    enabled: "boolean",
    mode: "string",
    simulation: "boolean",
    note: "string",
  });
  return rows(value, "providers", {
    name: "string",
    configured: "boolean",
    enabled: "boolean",
    active: "boolean",
  });
}
export function intelligence(value) {
  fields(value, {
    indicator: "string",
    mode: "string",
    simulation: "boolean",
    reputation_level: "string",
    normalized_score: "number?",
    checked_at: "string",
    expires_at: "string",
    stale: "boolean",
    configuration_changed: "boolean",
    explanation: "string",
    lookup_status: "string",
  });
  return rows(value, "providers", {
    provider: "string",
    explanation: "string",
    lookup_status: "string",
    simulation: "boolean",
    normalized_score: "number?",
    country: "string?",
    isp: "string?",
    reports: "number?",
  });
}
