import { api } from "./api";
import {
  assert,
  fields,
  rows,
  cursor,
  eventRows,
  incidentFields,
  providers,
} from "./contracts";
const contracts = {
  overview: (b) =>
    fields(
      b,
      Object.fromEntries(
        [
          "total_events",
          "events_in_range",
          "total_incidents",
          "active_incidents",
          "critical_incidents",
          "high_risk_incidents",
          "total_findings",
          "suspicious_ips",
          "unprocessed_events",
        ]
          .map((k) => [k, "number"])
          .concat([["average_risk_score", "number?"]]),
      ),
    ),
  "events/timeline": (b) => {
    fields(b, { total: "number", bucket_seconds: "number" });
    return rows(b, "data", {
      timestamp: "string",
      total: "number",
      login_failed: "number",
      access_denied: "number",
      api_requests: "number",
    });
  },
  "incidents/severity": (b) =>
    rows(fields(b, { total: "number" }), "distribution", {
      severity: "string",
      count: "number",
    }),
  "incidents/status": (b) =>
    rows(fields(b, { total: "number" }), "distribution", {
      status: "string",
      count: "number",
    }),
  "risk/distribution": (b) =>
    rows(
      fields(b, { total: "number", average_risk_score: "number?" }),
      "distribution",
      { level: "string", count: "number" },
    ),
  "events/types": (b) =>
    rows(fields(b, { total: "number" }), "distribution", {
      event_type: "string",
      count: "number",
    }),
  "events/recent": (b) => {
    eventRows(b);
    cursor(b.polling_cursor);
    return b;
  },
  "events/updates": (b) => {
    eventRows(b);
    cursor(b.next_cursor);
    cursor(b.head_cursor);
    fields(b, { has_more: "boolean" });
    return b;
  },
  "incidents/recent": (b) => rows(b, "items", incidentFields),
  "threats/top-ips": (b) =>
    rows(b, "items", {
      ip: "string",
      incident_count: "number",
      finding_count: "number",
      highest_risk_score: "number?",
      latest_activity: "string",
      reputation_level: "string",
      intelligence_status: "string",
      simulation: "boolean",
    }),
  "users/targeted": (b) =>
    rows(b, "items", {
      username: "string",
      failed_logins: "number",
      access_denials: "number",
      finding_count: "number",
      incident_count: "number",
    }),
  "detection/rules": (b) =>
    rows(b, "items", {
      rule_id: "string",
      name: "string",
      enabled: "boolean",
      severity: "string",
      finding_count: "number",
      latest_finding_timestamp: "string?",
    }),
  "threats/summary": (b) => {
    fields(b, {
      mode: "string",
      simulation: "boolean",
      cached_indicators: "number",
      malicious_indicators: "number",
      suspicious_indicators: "number",
      unknown_indicators: "number",
      expired_indicators: "number",
      incompatible_indicators: "number",
      last_refresh: "string?",
    });
    providers(b.providers);
    return b;
  },
  "activity/summary": (b) =>
    fields(
      b,
      Object.fromEntries(
        [
          "successful_logins",
          "failed_logins",
          "access_denials",
          "api_requests",
          "sensitive_record_accesses",
          "privilege_changes",
        ].map((k) => [k, "number"]),
      ),
    ),
  "system/health": (b) => {
    fields(b, {
      as_of: "string",
      api: "string",
      database: "string",
      total_events: "number",
      latest_event_timestamp: "string?",
      ai_analyst: "object",
    });
    fields(b.detection_engine, {
      status: "string",
      events_processed: "number",
      unprocessed_events: "number",
      last_processing_time: "string?",
      last_processing_duration_ms: "number?",
    });
    providers(b.threat_intelligence);
    return b;
  },
};
export async function dashboardGet(endpoint, params = {}, signal) {
  const { data } = await api.get(`/dashboard/${endpoint}`, { params, signal });
  assert(contracts[endpoint]);
  return contracts[endpoint](data);
}
