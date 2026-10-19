import { beforeEach, expect, it, vi } from "vitest";
import {
  fireEvent,
  render,
  screen,
  waitFor,
  within,
} from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import Analytics from "../pages/Analytics";
import { DashboardProvider } from "../context/DashboardContext";
import { api } from "../services/api";
import { analyticsGet } from "../services/analyticsApi";
const auth = vi.hoisted(() => ({
  user: { id: "analytics-user", role: "ADMIN", username: "admin" },
}));
vi.mock("../context/AuthContext", () => ({ useAuth: () => auth }));
// Real chart layout is checked separately in Chromium; jsdom has no layout engine.
vi.mock("../components/analytics/AnalyticsCharts", () => ({
  TrendChart: ({ data }) => (
    <div data-testid="trend-chart">Trend buckets: {data.length}</div>
  ),
  ComparisonChart: ({ data }) => (
    <div data-testid="comparison-chart">Comparison buckets: {data.length}</div>
  ),
}));
const scope = {
  start: "2026-10-01T00:00:00Z",
  end: "2026-10-14T00:00:00Z",
  as_of: "2026-10-14T00:00:00Z",
};
const base = { scope, definition: "Controlled fixture; UTC half-open period." };
const overview = {
  ...base,
  total_events: 10000,
  detection_findings: 37,
  incidents_created: 12,
  critical_incidents: 3,
  resolved_incidents: 6,
  false_positives: 2,
  average_risk_score: 65.5,
  median_risk_score: 63,
  unique_suspicious_ips: 8,
  unique_targeted_users: 7,
  acknowledged_incidents: 6,
  measured_resolutions: 6,
  mean_time_to_acknowledge_seconds: 300,
  mean_time_to_resolve_seconds: 7200,
  p90_resolution_seconds: 10800,
  resolution_rate: 50,
  false_positive_rate: 25,
};
const point = {
  timestamp: scope.start,
  created: 12,
  resolved: 6,
  false_positive: 2,
  reopened: 1,
  count: 12,
  average_risk: 65.5,
  median_risk: 63,
  maximum_risk: 90,
  critical_count: 3,
  total: 10000,
  login_failed: 20,
  access_denied: 5,
  api_requests: 100,
  sensitive_access: 4,
  privilege_changes: 1,
};
const rules = [
  {
    rule_id: "CS-001",
    name: "Brute Force",
    enabled: true,
    findings: 6,
    incidents: 4,
    average_risk: 75,
    critical_incidents: 2,
    false_positives: 1,
    closed_incidents: 2,
    false_positive_rate: 50,
    latest_detection: scope.start,
  },
  {
    rule_id: "CS-002",
    name: "Password Spray",
    enabled: false,
    findings: 9,
    incidents: 3,
    average_risk: 50,
    critical_incidents: 0,
    false_positives: 0,
    closed_incidents: 0,
    false_positive_rate: null,
    latest_detection: scope.start,
  },
];
let data;
function mount(path = "/analytics") {
  return render(
    <MemoryRouter initialEntries={[path]}>
      <DashboardProvider>
        <Analytics />
      </DashboardProvider>
    </MemoryRouter>,
  );
}
function tab(name) {
  fireEvent.click(screen.getByRole("tab", { name, exact: true }));
}
beforeEach(() => {
  auth.user.role = "ADMIN";
  data = {
    overview: structuredClone(overview),
    "incidents/trend": { ...base, data: [point] },
    "risk/trend": { ...base, data: [point] },
    "events/trend": { ...base, total: 10000, data: [point] },
    "incidents/status-history": {
      ...base,
      tracked_cases: 12,
      excluded_cases: 0,
      data: [
        {
          timestamp: scope.start,
          open: 3,
          investigating: 1,
          resolved: 6,
          false_positive: 2,
          unresolved: 4,
        },
      ],
    },
    "detections/rules": { ...base, items: rules },
    "risk/histogram": {
      ...base,
      total: 12,
      data: [{ label: "70–79", count: 4 }],
    },
    categories: {
      ...base,
      items: [{ category: "Authentication Abuse", findings: 15, incidents: 7 }],
    },
    geography: {
      ...base,
      items: [{ country: "India", finding_count: 15, incident_count: 7 }],
    },
    "detections/evaluation": {
      ...base,
      label: "Synthetic Evaluation Only",
      expected_scenarios: 5,
      detected_scenarios: 4,
      missed_scenarios: 1,
      unexpected_findings: 2,
      findings_evaluated: 6,
      scenario_recall: 0.8,
      finding_label_agreement: 0.67,
      precision: null,
      precision_note: "Agreement is not precision.",
    },
    "incidents/backlog": {
      ...base,
      open_count: 3,
      investigating_count: 1,
      critical_unresolved: 1,
      average_age_seconds: 7200,
      oldest: {
        incident_id: "INC-1",
        age_seconds: 10800,
        created_at: scope.start,
      },
      age_distribution: [{ label: "1–4 hours", count: 4 }],
    },
    "entities/high-risk": {
      ...base,
      kind: "username",
      limit: 20,
      has_more: false,
      items: [
        {
          entity: "employee014",
          event_count: 24,
          suspicious_event_count: 15,
          failed_logins: 14,
          access_denials: 1,
          incident_count: 4,
          finding_count: 6,
          average_risk: 75,
          highest_risk: 90,
          critical_incidents: 2,
          latest_activity: scope.start,
          first_seen: scope.start,
          detection_rules: ["CS-001"],
        },
      ],
    },
    "analysts/workload": {
      ...base,
      limit: 100,
      has_more: false,
      unassigned: 4,
      assigned_to_ineligible: 0,
      activity: [
        {
          timestamp: scope.start,
          assignments: 3,
          comments: 4,
          status_transitions: 6,
          resolutions: 2,
        },
      ],
      items: [
        {
          analyst_id: "1",
          username: "admin",
          assigned: 4,
          open: 1,
          investigating: 1,
          resolved: 2,
          average_resolution_seconds: 7200,
        },
      ],
    },
    "ai/usage": {
      ...base,
      analyses_generated: 5,
      fallback_analyses: 4,
      provider_analyses: 1,
      analysis_failures: 0,
      cache_hits: 2,
      average_response_ms: 123,
      stale_analyses: null,
      stale_measurement: "Computed per incident.",
    },
    "threat-intelligence": {
      ...base,
      modes: ["mock", "live"].map((mode) => ({
        mode,
        simulation: mode === "mock",
        indicators_checked: mode === "mock" ? 4 : 0,
        malicious: 1,
        suspicious: 1,
        unknown: 2,
        no_adverse_signals: 0,
        expired: 1,
        cache_hits: 2,
        lookups: 6,
        provider_failures: 0,
        provider_usage: [],
      })),
    },
  };
  vi.spyOn(api, "get").mockImplementation(async (url) => {
    if (url.startsWith("/analytics/"))
      return { data: structuredClone(data[url.slice("/analytics/".length)]) };
    if (url.startsWith("/reports/"))
      return {
        data: new Blob(['"incident_id"\r\n"INC-1"'], { type: "text/csv" }),
        headers: {
          "content-type": "text/csv; charset=utf-8",
          "x-export-rows": "1",
          "x-export-has-more": "false",
        },
      };
    throw new Error(url);
  });
  URL.createObjectURL = vi.fn(() => "blob:test");
  URL.revokeObjectURL = vi.fn();
  vi.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(() => {});
});
it("loads executive KPIs, real metric definitions, and trend data", async () => {
  mount();
  expect(await screen.findByText("10,000")).toBeVisible();
  expect(screen.getByText("65.5")).toBeVisible();
  expect(screen.getByText("50%")).toBeVisible();
  expect(screen.getAllByTestId("trend-chart")).toHaveLength(2);
  fireEvent.click(screen.getByText("Scope & metric definition"));
  expect(screen.getByText(base.definition)).toBeVisible();
});
it("uses one exact UTC interval across widgets and preserves it across tabs", async () => {
  mount();
  await screen.findByText("10,000");
  fireEvent.click(screen.getByRole("button", { name: "90D", exact: true }));
  await waitFor(() => {
    const calls = api.get.mock.calls.filter(
      ([url]) => url === "/analytics/overview",
    );
    const p = calls.at(-1)[1].params;
    expect(new Date(p.end) - new Date(p.start)).toBe(90 * 86400000);
  });
  const expected = api.get.mock.calls
    .filter(([url]) => url === "/analytics/overview")
    .at(-1)[1].params;
  tab("Detection performance");
  await screen.findByText("Brute Force");
  expect(
    api.get.mock.calls
      .filter(([url]) => url === "/analytics/detections/rules")
      .at(-1)[1].params,
  ).toEqual(expected);
});
it("validates and applies a custom UTC range without changing other section state", async () => {
  mount();
  await screen.findByText("10,000");
  fireEvent.click(screen.getByRole("button", { name: "Custom range" }));
  fireEvent.change(screen.getByLabelText("Start (UTC)"), {
    target: { value: "2026-10-14T10:00" },
  });
  fireEvent.change(screen.getByLabelText("End (UTC)"), {
    target: { value: "2026-10-13T10:00" },
  });
  fireEvent.click(screen.getByRole("button", { name: "Apply custom range" }));
  expect(screen.getByRole("alert")).toHaveTextContent("ordered UTC range");
  fireEvent.change(screen.getByLabelText("Start (UTC)"), {
    target: { value: "2026-10-01T10:00" },
  });
  fireEvent.click(screen.getByRole("button", { name: "Apply custom range" }));
  await waitFor(() =>
    expect(
      api.get.mock.calls
        .filter(([url]) => url === "/analytics/overview")
        .at(-1)[1].params,
    ).toEqual({
      start: "2026-10-01T10:00:00.000Z",
      end: "2026-10-13T10:00:00.000Z",
    }),
  );
});
it("renders zero counts and unavailable timing as distinct states", async () => {
  data.overview = {
    ...overview,
    total_events: 0,
    detection_findings: 0,
    incidents_created: 0,
    critical_incidents: 0,
    resolved_incidents: 0,
    false_positives: 0,
    resolution_rate: null,
    false_positive_rate: null,
    average_risk_score: null,
    median_risk_score: null,
    mean_time_to_acknowledge_seconds: null,
    mean_time_to_resolve_seconds: null,
    p90_resolution_seconds: null,
  };
  mount();
  await screen.findByText("Incidents created");
  expect(screen.getAllByText("—").length).toBeGreaterThan(3);
  expect(screen.queryByText("NaN")).not.toBeInTheDocument();
});
it("sorts the detection table and labels synthetic evaluation explicitly", async () => {
  mount("/analytics?section=detections");
  await screen.findByText("Brute Force");
  let rows = within(
    screen.getByRole("table", { name: "Detection performance" }),
  ).getAllByRole("row");
  expect(rows[1]).toHaveTextContent("CS-002");
  fireEvent.change(screen.getByLabelText("Sort detection rules"), {
    target: { value: "rule_id" },
  });
  rows = within(
    screen.getByRole("table", { name: "Detection performance" }),
  ).getAllByRole("row");
  expect(rows[1]).toHaveTextContent("CS-001");
  expect(screen.getByText("Synthetic Evaluation Only")).toBeVisible();
  expect(screen.getByText(/Agreement is not precision/)).toBeVisible();
});
it("renders incident backlog, audit history and source incident link", async () => {
  mount("/analytics?section=incidents");
  expect(await screen.findByRole("link", { name: "INC-1" })).toHaveAttribute(
    "href",
    "/incidents/INC-1",
  );
  expect(screen.getByText("Recorded status & backlog over time")).toBeVisible();
  expect(screen.getByText("Critical unresolved")).toBeVisible();
});
it("changes entity and risk populations through scoped API requests", async () => {
  mount("/analytics?section=risk");
  await screen.findByText("employee014");
  fireEvent.change(screen.getByLabelText("Entity type"), {
    target: { value: "source_ip" },
  });
  fireEvent.click(screen.getByLabelText("Recurring sources only"));
  await waitFor(() =>
    expect(
      api.get.mock.calls.some(
        ([url, cfg]) =>
          url === "/analytics/entities/high-risk" && cfg.params.recurring_only,
      ),
    ).toBe(true),
  );
  fireEvent.change(screen.getByLabelText("Risk population"), {
    target: { value: "findings" },
  });
  await waitFor(() =>
    expect(
      api.get.mock.calls.some(
        ([url, cfg]) =>
          url === "/analytics/risk/trend" &&
          cfg.params.population === "findings",
      ),
    ).toBe(true),
  );
});
it("renders workload for administrators and hides it from analysts", async () => {
  const view = mount("/analytics?section=operations");
  expect(
    await screen.findByRole("table", { name: "Analyst workload" }),
  ).toBeVisible();
  view.unmount();
  auth.user.role = "ANALYST";
  api.get.mockClear();
  mount("/analytics?section=operations");
  await screen.findByText("Analyses generated");
  expect(
    screen.getByText(/Individual analyst workload is restricted/),
  ).toBeVisible();
  expect(
    api.get.mock.calls.some(([url]) => url === "/analytics/analysts/workload"),
  ).toBe(false);
});
it("separates mock and live intelligence", async () => {
  mount("/analytics?section=intelligence");
  expect(await screen.findByText("Simulated intelligence")).toBeVisible();
  expect(screen.getByText("Live-provider intelligence")).toBeVisible();
});
it("applies event filters without silently changing the category population", async () => {
  mount("/analytics?section=trends");
  await screen.findByText("India");
  fireEvent.change(screen.getByLabelText("Event type"), {
    target: { value: "LOGIN_FAILED" },
  });
  fireEvent.click(screen.getByRole("button", { name: "Apply event filters" }));
  await waitFor(() =>
    expect(
      api.get.mock.calls.some(
        ([url, cfg]) =>
          url === "/analytics/events/trend" &&
          cfg.params.event_type === "LOGIN_FAILED",
      ),
    ).toBe(true),
  );
  expect(
    api.get.mock.calls
      .filter(([url]) => url === "/analytics/categories")
      .every(([, cfg]) => cfg.params.event_type === undefined),
  ).toBe(true);
});
it("exports on explicit submit, shows success, and does not create a public link", async () => {
  mount("/analytics?section=reports");
  expect(api.get.mock.calls.some(([url]) => url.startsWith("/reports/"))).toBe(
    false,
  );
  fireEvent.click(screen.getByRole("button", { name: "Generate report" }));
  expect(await screen.findByRole("status")).toHaveTextContent(
    "Downloaded 1 rows",
  );
  expect(URL.createObjectURL).toHaveBeenCalledOnce();
  expect(HTMLAnchorElement.prototype.click).toHaveBeenCalledOnce();
});
it("handles export errors and permits retry", async () => {
  api.get.mockRejectedValueOnce({
    response: { status: 503, data: { detail: "Database unavailable" } },
  });
  mount("/analytics?section=reports");
  fireEvent.click(screen.getByRole("button", { name: "Generate report" }));
  expect(await screen.findByRole("alert")).toHaveTextContent(
    "Database unavailable",
  );
  expect(screen.getByRole("button", { name: "Generate report" })).toBeEnabled();
});
it("restricts viewer exports and analyst workload exports in the UI", () => {
  auth.user.role = "VIEWER";
  const view = mount("/analytics?section=reports");
  expect(screen.getByText(/Report downloads require/)).toBeVisible();
  expect(
    screen.queryByRole("button", { name: "Generate report" }),
  ).not.toBeInTheDocument();
  view.unmount();
  auth.user.role = "ANALYST";
  mount("/analytics?section=reports");
  expect(
    screen.queryByRole("option", { name: "Analyst workload" }),
  ).not.toBeInTheDocument();
});
it("rejects malformed numeric API contracts instead of showing invented zeros", async () => {
  api.get.mockResolvedValue({ data: { ...base, incidents_created: "twelve" } });
  await expect(analyticsGet("overview", {})).rejects.toThrow();
});
