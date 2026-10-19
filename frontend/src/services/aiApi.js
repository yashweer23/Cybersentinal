import { api } from "./api";
import { fields, assert, rows } from "./contracts";
const base = (id) => `/ai/incidents/${encodeURIComponent(id)}`;
function references(data) {
  rows(data, "references", {
    reference_id: "string",
    kind: "string",
    label: "string",
  });
  return data;
}
export function validateAnalysis(data) {
  fields(data, {
    analysis_id: "string",
    incident_id: "string",
    analysis_mode: "string",
    summary: "string",
    why_flagged: "string",
    potential_impact: "string",
    uncertainty: "string",
    generated_at: "string",
    is_current: "boolean",
    stale: "boolean",
    cached: "boolean",
    provider: "string",
    model: "string?",
    generated_by_user_id: "string?",
    coverage: "object",
    investigation_steps: "array",
    recommended_actions: "array",
    risk_explanation: "array",
    key_evidence: "array",
    fallback_reason: "string?",
  });
  assert(["AI", "FALLBACK"].includes(data.analysis_mode));
  references(data);
  for (const key of ["key_evidence", "risk_explanation"]) {
    rows(data, key, { statement: "string", reference_ids: "array" });
    for (const item of data[key])
      assert(
        item.reference_ids.every((id) =>
          data.references.some((ref) => ref.reference_id === id),
        ),
      );
  }
  for (const key of ["investigation_steps", "recommended_actions"])
    assert(data[key].every((value) => typeof value === "string"));
  return data;
}
export async function getAIStatus(signal) {
  const { data } = await api.get("/ai/status", { signal });
  return fields(data, {
    enabled: "boolean",
    configured: "boolean",
    mode: "string",
    status: "string",
    provider: "string",
    note: "string",
  });
}
export async function readAnalysis(id, signal) {
  const { data } = await api.get(`${base(id)}/analysis`, { signal });
  fields(data, { analysis: "object?" });
  if (data.analysis) validateAnalysis(data.analysis);
  return data;
}
export async function analysisHistory(id, offset, signal) {
  const { data } = await api.get(`${base(id)}/history`, {
    params: { limit: 5, offset },
    signal,
  });
  fields(data, {
    items: "array",
    total: "number",
    limit: "number",
    offset: "number",
  });
  data.items.forEach(validateAnalysis);
  return data;
}
export async function analyzeIncident(id, force_refresh) {
  const { data } = await api.post(
    `${base(id)}/analyze`,
    { force_refresh },
    { timeout: 90000 },
  );
  return validateAnalysis(data);
}
export async function askIncident(id, question) {
  const { data } = await api.post(
    `${base(id)}/ask`,
    { question },
    { timeout: 90000 },
  );
  fields(data, {
    answer: "string",
    analysis_mode: "string",
    evidence_ids: "array",
    uncertainty: "string",
    confidence: "string",
    context_hash: "string",
  });
  return references(data);
}
export async function askOverview(question) {
  const { data } = await api.post("/ai/overview/ask", { question });
  return fields(data, {
    answer: "string",
    evidence: "array",
    scope: "string",
    analysis_mode: "string",
    note: "string",
    total: "number",
    truncated: "boolean",
  });
}
