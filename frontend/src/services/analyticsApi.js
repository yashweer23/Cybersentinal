import { api, errorMessage } from "./api";
import { fields, rows, assert } from "./contracts";
const itemContracts = {
  "detections/rules": {
    rule_id: "string",
    name: "string",
    enabled: "boolean",
    findings: "number",
    incidents: "number",
    average_risk: "number?",
    false_positive_rate: "number?",
  },
  "entities/high-risk": {
    entity: "string",
    incident_count: "number",
    finding_count: "number",
    highest_risk: "number?",
    average_risk: "number?",
  },
  "analysts/workload": {
    username: "string",
    assigned: "number",
    open: "number",
    investigating: "number",
    resolved: "number",
    average_resolution_seconds: "number?",
  },
  categories: { category: "string", findings: "number", incidents: "number" },
  geography: {
    country: "string",
    finding_count: "number",
    incident_count: "number",
  },
};
export async function analyticsGet(endpoint, params, signal) {
  const { data } = await api.get(`/analytics/${endpoint}`, { params, signal });
  fields(data, { scope: "object", definition: "string" });
  fields(data.scope, { start: "string", end: "string", as_of: "string" });
  if (itemContracts[endpoint]) rows(data, "items", itemContracts[endpoint]);
  else if (
    endpoint.endsWith("/trend") ||
    endpoint === "incidents/status-history"
  )
    rows(data, "data", { timestamp: "string" });
  else if (endpoint === "risk/histogram")
    rows(data, "data", { label: "string", count: "number" });
  else if (endpoint === "overview")
    fields(data, {
      incidents_created: "number",
      total_events: "number",
      detection_findings: "number",
      resolution_rate: "number?",
      mean_time_to_resolve_seconds: "number?",
      false_positive_rate: "number?",
    });
  else if (endpoint === "incidents/backlog") {
    fields(data, {
      open_count: "number",
      investigating_count: "number",
      critical_unresolved: "number",
      average_age_seconds: "number?",
    });
    rows(data, "age_distribution", { label: "string", count: "number" });
  } else if (endpoint === "threat-intelligence")
    rows(data, "modes", {
      mode: "string",
      simulation: "boolean",
      indicators_checked: "number",
      malicious: "number",
      unknown: "number",
    });
  else if (endpoint === "ai/usage")
    fields(data, {
      analyses_generated: "number",
      fallback_analyses: "number",
      provider_analyses: "number",
      stale_analyses: "number?",
    });
  else if (endpoint === "detections/evaluation")
    fields(data, {
      label: "string",
      expected_scenarios: "number",
      detected_scenarios: "number",
      scenario_recall: "number?",
      precision: "number?",
    });
  else assert(false);
  return data;
}
export async function downloadReport(kind, params, signal) {
  try {
    const response = await api.get(`/reports/${kind}`, {
      params,
      signal,
      responseType: "blob",
      timeout: 60000,
    });
    const mime = response.headers["content-type"] || "";
    assert(
      mime.includes(params.format === "csv" ? "text/csv" : "application/json"),
    );
    return response;
  } catch (error) {
    if (error.response?.data instanceof Blob) {
      try {
        error.response.data = JSON.parse(await error.response.data.text());
      } catch {
        /* Keep safe generic error. */
      }
    }
    throw new Error(errorMessage(error, "Report export failed. Please retry."));
  }
}
