import { api } from "./api";
import { fields, rows, incidentFields, intelligence } from "./contracts";
export async function listIncidents(params, signal) {
  const { data } = await api.get("/incidents", { params, signal });
  fields(data, { total: "number", limit: "number", offset: "number" });
  return rows(data, "items", incidentFields);
}
export async function getIncident(id, signal) {
  const { data } = await api.get(`/incidents/${encodeURIComponent(id)}`, {
    signal,
  });
  fields(data, {
    ...incidentFields,
    description: "string",
    confidence: "number",
    first_seen: "string",
    last_seen: "string",
    findings: "object",
    evidence_total: "number",
    allowed_transitions: "array",
    risk_assessment: "object?",
  });
  if (data.risk_assessment) validateRisk(data.risk_assessment);
  return data;
}

const base = (id) => `/incidents/${encodeURIComponent(id)}`;
export function validateRisk(data) {
  fields(data, {
    assessment_id: "string",
    finding_id: "string",
    risk_score: "number",
    risk_level: "string",
    breakdown: "object",
    calculated_at: "string",
    score_version: "string",
  });
  for (const name of [
    "severity",
    "confidence",
    "behavioural_intensity",
    "event_frequency",
    "asset_sensitivity",
    "reputation",
  ])
    fields(data.breakdown[name], {
      points: "number",
      max: "number",
      reason: "string",
    });
  return data;
}
const specs = {
  findings: {
    finding_id: "string",
    rule_id: "string",
    rule_name: "string",
    title: "string",
    severity: "string",
    confidence: "number",
    event_count: "number",
    risk_score: "number?",
    assessment_id: "string?",
    first_seen: "string",
    last_seen: "string",
    relationship_reason: "string",
    correlation_data: "object",
  },
  events: {
    id: "string",
    event_id: "string",
    timestamp: "string",
    event_type: "string",
    source_ip: "string",
    destination_ip: "string?",
    source_port: "number?",
    destination_port: "number?",
    username: "string?",
    service: "string?",
    status: "string",
  },
  timeline: {
    timestamp: "string",
    type: "string",
    title: "string",
    reference_id: "string",
    actor_username: "string?",
    details: "object",
  },
  comments: {
    id: "string",
    comment: "string",
    author: "object?",
    created_at: "string",
  },
};
export async function incidentSection(id, section, params, signal) {
  const { data } = await api.get(`${base(id)}/${section}`, { params, signal });
  if (section === "threat-intelligence") {
    fields(data, {
      indicators: "array",
      missing_indicators: "array",
      total_indicators: "number",
      limit: "number",
      offset: "number",
      mode: "string",
    });
    data.indicators.forEach(intelligence);
    return data;
  }
  fields(data, { total: "number", limit: "number", offset: "number" });
  return rows(data, "items", specs[section]);
}
export async function getFinding(id, signal) {
  const { data } = await api.get(`/detections/${encodeURIComponent(id)}`, {
    signal,
  });
  return fields(data, {
    finding_id: "string",
    description: "string",
    evidence_data: "object",
    evidence_event_ids: "array",
    event_count: "number",
  });
}
export async function getRisk(id, signal) {
  const { data } = await api.get(`/risk/${encodeURIComponent(id)}`, { signal });
  return validateRisk(data);
}
export async function getEvent(id, signal) {
  const { data } = await api.get(`/events/${encodeURIComponent(id)}`, {
    signal,
  });
  return fields(data, { ...specs.events, raw_data: "object" });
}
export async function eligibleAnalysts(params, signal) {
  const { data } = await api.get("/incidents/eligible-analysts", {
    params,
    signal,
  });
  fields(data, { total: "number", limit: "number", offset: "number" });
  return rows(data, "items", {
    id: "string",
    username: "string",
    full_name: "string?",
    role: "string",
    is_active: "boolean",
  });
}
export async function assignIncident(id, analyst_id) {
  const { data } = await api.patch(`${base(id)}/assign`, { analyst_id });
  return fields(data, incidentFields);
}
export async function changeIncidentStatus(id, payload) {
  const { data } = await api.patch(`${base(id)}/status`, payload);
  return fields(data, incidentFields);
}
export async function addIncidentComment(id, comment) {
  const { data } = await api.post(`${base(id)}/comments`, { comment });
  return fields(data, specs.comments);
}
export async function refreshIncidentIntelligence(id) {
  // Explicit, auditable case enrichment. Long-running lookups have a server-side time budget.
  const { data } = await api.post(
    "/threats/enrich/incidents",
    { incident_id: id, force_refresh: true, limit: 1 },
    { timeout: 330000 },
  );
  return fields(data, {
    complete: "boolean",
    failed_lookups: "number",
    indicators_evaluated: "number",
    unknown_lookups: "number",
    simulation: "boolean",
  });
}
