import {
  fireEvent,
  render,
  screen,
  waitFor,
  within,
} from "@testing-library/react";
import { beforeEach, expect, it, vi } from "vitest";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { api } from "../services/api";
import { DashboardProvider } from "../context/DashboardContext";
import IncidentInvestigation from "../pages/IncidentInvestigation";
import Incidents from "../pages/Incidents";
import { incident as basic, at, threat } from "./fixtures";
const auth = vi.hoisted(() => ({
  user: {
    id: "operator-1",
    username: "analyst",
    full_name: "Test Analyst",
    role: "ANALYST",
  },
}));
vi.mock("../context/AuthContext", () => ({ useAuth: () => auth }));
const analyst = { ...auth.user, is_active: true };
const components = {
  severity: 20,
  confidence: 14,
  behavioural_intensity: 17,
  event_frequency: 12,
  asset_sensitivity: 15,
  reputation: 10,
};
const risk = {
  assessment_id: "RISK-1",
  finding_id: "FIND-1",
  risk_score: 88,
  risk_level: "CRITICAL",
  calculated_at: at,
  score_version: "v1",
  breakdown: Object.fromEntries(
    Object.entries(components).map(([k, points]) => [
      k,
      {
        points,
        max: {
          severity: 25,
          confidence: 15,
          behavioural_intensity: 20,
          event_frequency: 15,
          asset_sensitivity: 15,
          reputation: 10,
        }[k],
        reason: `Stored reason for ${k}`,
      },
    ]),
  ),
};
const finding = {
  finding_id: "FIND-1",
  rule_id: "CS-001",
  rule_name: "Brute Force Detection",
  title: "Repeated authentication failures",
  severity: "HIGH",
  confidence: 94,
  risk_score: 88,
  risk_level: "CRITICAL",
  assessment_id: "RISK-1",
  source_ip: basic.source_ip,
  username: basic.username,
  first_seen: at,
  last_seen: at,
  event_count: 32,
  relationship_reason: "Same account and source within the correlation window",
  correlation_data: { same_source_ip: true, same_username: true },
};
const event = {
  id: "event-1",
  event_id: "EVT-1",
  timestamp: at,
  event_type: "LOGIN_FAILED",
  source_ip: basic.source_ip,
  destination_ip: "10.0.0.12",
  username: basic.username,
  service: "authentication",
  status: "failed",
  source_port: 53210,
  destination_port: 443,
  country: "India",
  device: "LT-HYD-014",
  user_agent: "test-agent",
  raw_data: { endpoint: "<script>alert('xss')</script>", attempt: 1 },
};
const page = (items, options = {}) => ({
  items,
  total: items.length,
  limit: 20,
  offset: 0,
  ...options,
});
let incident, notes, timeline, related;
const transitions = {
  OPEN: ["INVESTIGATING", "FALSE_POSITIVE"],
  INVESTIGATING: ["RESOLVED", "FALSE_POSITIVE"],
  RESOLVED: ["INVESTIGATING"],
  FALSE_POSITIVE: ["INVESTIGATING"],
};
function response(url, config = {}) {
  let data;
  if (url === "/incidents") data = page([incident]);
  else if (url === "/incidents/eligible-analysts") data = page([analyst]);
  else if (url === "/incidents/INC-TEST-001")
    data = {
      ...incident,
      allowed_transitions:
        auth.user.role === "VIEWER" ? [] : transitions[incident.status],
    };
  else if (url.endsWith("/findings")) data = page([finding]);
  else if (url.endsWith("/events")) data = page([event]);
  else if (url.endsWith("/timeline"))
    data = page(
      config.params?.order === "desc" ? [...timeline].reverse() : timeline,
    );
  else if (url.endsWith("/comments")) data = page(notes);
  else if (url.endsWith("/threat-intelligence")) data = related;
  else if (url === "/detections/FIND-1")
    data = {
      ...finding,
      description: "32 failures within 91 seconds",
      evidence_event_ids: ["EVT-1"],
      evidence_data: { attempt_count: 32, threshold: 5, duration_seconds: 91 },
    };
  else if (url === "/risk/RISK-1") data = risk;
  else if (url === "/events/EVT-1") data = event;
  else throw new Error("Unexpected request " + url);
  return { data: structuredClone(data) };
}
beforeEach(() => {
  auth.user = { ...analyst, role: "ANALYST" };
  incident = {
    ...basic,
    severity: "CRITICAL",
    risk_score: 88,
    first_seen: at,
    last_seen: at,
    updated_at: at,
    assigned_analyst_id: null,
    risk_assessment: risk,
    findings: page([finding]),
    evidence_total: 1,
    allowed_transitions: transitions.OPEN,
    resolution_summary: null,
    resolved_at: null,
  };
  notes = [
    {
      id: "note-1",
      comment: "Initial evidence review.",
      created_at: at,
      updated_at: at,
      author: analyst,
    },
  ];
  timeline = [
    {
      timestamp: "2026-10-10T07:00:00Z",
      type: "SECURITY_EVENT",
      title: "LOGIN_FAILED",
      reference_id: "EVT-1",
      actor_username: null,
      details: { username: "employee014", source_ip: basic.source_ip },
    },
    {
      timestamp: "2026-10-10T07:02:00Z",
      type: "DETECTION",
      title: "Brute force detected",
      reference_id: "FIND-1",
      actor_username: null,
      details: {},
    },
  ];
  related = {
    mode: "mock",
    total_indicators: 1,
    limit: 10,
    offset: 0,
    missing_indicators: [],
    indicators: [
      {
        ...threat,
        expires_at: "2099-10-10T08:00:00Z",
        providers: [
          {
            provider: "CyberSentinel Mock",
            explanation: "Synthetic observation.",
            lookup_status: "success",
            simulation: true,
            normalized_score: 90,
            country: "India",
            isp: "Example ISP",
            reports: null,
          },
        ],
      },
    ],
  };
  vi.spyOn(api, "get").mockImplementation(async (url, config) =>
    response(url, config),
  );
  vi.spyOn(api, "patch").mockImplementation(async (url, payload) => {
    if (url.endsWith("/assign")) {
      incident.assigned_analyst_id = payload.analyst_id;
      incident.assigned_analyst = payload.analyst_id ? analyst : null;
    }
    if (url.endsWith("/status")) {
      incident.status = payload.status;
      incident.allowed_transitions = transitions[payload.status];
      incident.resolution_summary =
        payload.resolution_summary || payload.reason || null;
    }
    return { data: structuredClone(incident) };
  });
  vi.spyOn(api, "post").mockImplementation(async (url, payload) => {
    if (url === "/threats/enrich/incidents")
      return {
        data: {
          complete: true,
          failed_lookups: 0,
          unknown_lookups: 0,
          indicators_evaluated: 1,
          simulation: true,
        },
      };
    const note = {
      id: "note-2",
      comment: payload.comment,
      author: analyst,
      created_at: at,
      updated_at: at,
    };
    notes.push(note);
    return { data: note };
  });
});
function mount(search = "") {
  return render(
    <MemoryRouter initialEntries={[`/incidents/INC-TEST-001${search}`]}>
      <DashboardProvider>
        <Routes>
          <Route
            path="/incidents/:incident_id"
            element={<IncidentInvestigation />}
          />
          <Route path="/incidents" element={<Incidents />} />
        </Routes>
      </DashboardProvider>
    </MemoryRouter>,
  );
}
const loaded = () =>
  screen.findByRole("heading", { name: "Possible brute force activity" });
const tab = async (name) => {
  fireEvent.click(screen.getByRole("tab", { name }));
};

it("loads a direct incident link with metadata, stored component reasons and a skeleton", async () => {
  mount();
  expect(screen.getByRole("status", { name: "Loading data" })).toBeVisible();
  await loaded();
  expect(
    screen.getByText("Stored reason for behavioural_intensity"),
  ).toBeVisible();
  expect(
    screen.getByRole("progressbar", { name: "Detection severity" }),
  ).toHaveValue(20);
  expect(
    screen.getByText("Detection confidence", {
      selector: ".case-counters span",
    }),
  ).toBeVisible();
  expect(
    screen.getByText("198.51.100.73", { selector: ".case-header-meta dd" }),
  ).toBeVisible();
  expect(
    api.get.mock.calls.filter(([url]) => url === "/incidents/INC-TEST-001"),
  ).toHaveLength(1);
  expect(api.post).not.toHaveBeenCalled();
});
it("shows a 404 state with a queue link", async () => {
  api.get.mockRejectedValue({ response: { status: 404 } });
  mount();
  expect(await screen.findByText("Incident not found")).toBeVisible();
  expect(
    screen.getByRole("link", { name: "Back to incidents" }),
  ).toHaveAttribute("href", "/incidents");
});
it("isolates threat failures while keeping the incident and risk available", async () => {
  api.get.mockImplementation(async (url, config) => {
    if (url.endsWith("/threat-intelligence"))
      throw { response: { status: 403 } };
    return response(url, config);
  });
  mount();
  await loaded();
  expect(await screen.findByText("Data unavailable")).toBeVisible();
  expect(screen.getByText("Stored reason for reputation")).toBeVisible();
  fireEvent.click(screen.getByRole("button", { name: "Retry request" }));
});
it("expands structured finding evidence and preserves raw JSON as a secondary section", async () => {
  mount("?tab=findings");
  await loaded();
  fireEvent.click(
    await screen.findByRole("button", { name: "Inspect evidence" }),
  );
  expect(await screen.findByText("Failed attempts")).toBeVisible();
  expect(screen.getByText("Detection threshold")).toBeVisible();
  expect(screen.getByText("32 failures within 91 seconds")).toBeVisible();
  fireEvent.click(screen.getByText("View raw evidence"));
  expect(screen.getByLabelText("View raw evidence")).toHaveTextContent(
    '"attempt_count": 32',
  );
});
it("requests global timeline ordering on the server", async () => {
  mount("?tab=timeline");
  await loaded();
  await screen.findByText("Brute force detected");
  expect(
    [...document.querySelectorAll(".case-timeline h3")].map(
      (node) => node.textContent,
    ),
  ).toEqual(["LOGIN_FAILED", "Brute force detected"]);
  fireEvent.change(screen.getByLabelText("Timeline order"), {
    target: { value: "desc" },
  });
  await waitFor(() =>
    expect(document.querySelector(".case-timeline h3")).toHaveTextContent(
      "Brute force detected",
    ),
  );
  expect(api.get).toHaveBeenCalledWith(
    "/incidents/INC-TEST-001/timeline",
    expect.objectContaining({
      params: { limit: 20, offset: 0, order: "desc" },
    }),
  );
});
it("opens an escaped raw-event drawer, traps focus and returns it on Escape", async () => {
  mount("?tab=events");
  await loaded();
  const trigger = await screen.findByRole("button", {
    name: "View event EVT-1",
  });
  trigger.focus();
  fireEvent.click(trigger);
  const dialog = await screen.findByRole("dialog", {
    name: "Security event evidence",
  });
  expect(await within(dialog).findByText("LT-HYD-014")).toBeVisible();
  fireEvent.click(within(dialog).getByText("Raw event data"));
  expect(within(dialog).getByLabelText("Raw event data")).toHaveTextContent(
    "<script>",
  );
  expect(dialog.querySelector("script")).toBeNull();
  within(dialog).getByRole("button", { name: "Close dialog" }).focus();
  fireEvent.keyDown(document, { key: "Tab", shiftKey: true });
  expect(dialog.contains(document.activeElement)).toBe(true);
  fireEvent.keyDown(document, { key: "Escape" });
  expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
  expect(trigger).toHaveFocus();
});
it("filters incident evidence via bounded backend queries", async () => {
  mount("?tab=events");
  await loaded();
  await screen.findByRole("button", { name: "View event EVT-1" });
  fireEvent.change(screen.getByLabelText("Event service"), {
    target: { value: "authentication" },
  });
  fireEvent.click(screen.getByRole("button", { name: "Filter events" }));
  await waitFor(() =>
    expect(api.get).toHaveBeenCalledWith(
      "/incidents/INC-TEST-001/events",
      expect.objectContaining({
        params: { limit: 20, offset: 0, service: "authentication" },
      }),
    ),
  );
});
it("labels simulated intelligence, expands provider fields and refreshes exactly once", async () => {
  mount("?tab=threat-intelligence");
  await loaded();
  expect(await screen.findByText("Simulated intelligence")).toBeVisible();
  fireEvent.click(screen.getByText("Provider results (1)"));
  expect(screen.getByText("Example ISP")).toBeVisible();
  fireEvent.click(screen.getByRole("button", { name: "Refresh intelligence" }));
  await screen.findByText(/Intelligence refresh completed/);
  expect(api.post).toHaveBeenCalledTimes(1);
  expect(api.post).toHaveBeenCalledWith(
    "/threats/enrich/incidents",
    { incident_id: "INC-TEST-001", force_refresh: true, limit: 1 },
    expect.objectContaining({ timeout: 330000 }),
  );
});
it("keeps intelligence refresh disabled across tab remounts while a write is pending", async () => {
  let finish;
  api.post.mockImplementation(
    () =>
      new Promise((resolve) => {
        finish = resolve;
      }),
  );
  mount("?tab=threat-intelligence");
  await loaded();
  fireEvent.click(screen.getByRole("button", { name: "Refresh intelligence" }));
  await waitFor(() => expect(api.post).toHaveBeenCalledTimes(1));
  await tab("Notes");
  await tab("Threat intel");
  expect(
    screen.getByRole("button", { name: "Refreshing intelligence…" }),
  ).toBeDisabled();
  fireEvent.click(
    screen.getByRole("button", { name: "Refreshing intelligence…" }),
  );
  expect(api.post).toHaveBeenCalledTimes(1);
  finish({
    data: {
      complete: true,
      failed_lookups: 0,
      unknown_lookups: 0,
      indicators_evaluated: 1,
    },
  });
  await waitFor(() =>
    expect(
      screen.getByRole("button", { name: "Refresh intelligence" }),
    ).toBeEnabled(),
  );
});
it("shows partial provider failure rather than claiming a clean refresh", async () => {
  api.post.mockResolvedValue({
    data: {
      complete: false,
      failed_lookups: 1,
      unknown_lookups: 1,
      indicators_evaluated: 1,
      simulation: true,
      error: "Rate limit reached",
    },
  });
  mount("?tab=threat-intelligence");
  await loaded();
  fireEvent.click(screen.getByRole("button", { name: "Refresh intelligence" }));
  expect(await screen.findByText(/partially completed/)).toHaveTextContent(
    "Rate limit reached",
  );
});
it("submits a note only once, then reads the persisted comment", async () => {
  mount("?tab=notes");
  await loaded();
  await screen.findByText("Initial evidence review.");
  expect(screen.getByRole("button", { name: "Save note" })).toBeDisabled();
  fireEvent.change(screen.getByLabelText("Add investigation note"), {
    target: { value: "  Verified with the account owner.  " },
  });
  fireEvent.click(screen.getByRole("button", { name: "Save note" }));
  expect(await screen.findByText("Investigation note saved.")).toBeVisible();
  expect(screen.getByText("Verified with the account owner.")).toBeVisible();
  expect(api.post).toHaveBeenCalledTimes(1);
  expect(screen.getByLabelText("Add investigation note")).toHaveValue("");
});
it("preserves failed and unsaved notes across refresh and tab changes", async () => {
  api.post.mockRejectedValue({
    response: { status: 503, data: { detail: "Write unavailable" } },
  });
  mount("?tab=notes");
  await loaded();
  fireEvent.change(screen.getByLabelText("Add investigation note"), {
    target: { value: "Keep this draft" },
  });
  fireEvent.click(screen.getByRole("button", { name: "Refresh case" }));
  await tab("Overview");
  await tab("Notes");
  expect(screen.getByLabelText("Add investigation note")).toHaveValue(
    "Keep this draft",
  );
  fireEvent.click(screen.getByRole("button", { name: "Save note" }));
  expect(await screen.findByText("Write unavailable")).toBeVisible();
  expect(screen.getByLabelText("Add investigation note")).toHaveValue(
    "Keep this draft",
  );
  expect(
    screen.queryByText("Investigation note saved."),
  ).not.toBeInTheDocument();
});
it("assigns the current analyst using the existing assignment API", async () => {
  mount();
  await loaded();
  fireEvent.click(screen.getByRole("button", { name: "Assign", exact: true }));
  await screen.findByRole("radio", { name: /analyst/ });
  fireEvent.click(screen.getByRole("button", { name: "Assign to me" }));
  expect(await screen.findByText("Assignment saved.")).toBeVisible();
  expect(api.patch).toHaveBeenCalledWith("/incidents/INC-TEST-001/assign", {
    analyst_id: "operator-1",
  });
  expect(document.querySelector(".case-header-meta")).toHaveTextContent(
    "analyst",
  );
});
it("requires investigation before resolution and a resolution summary", async () => {
  mount();
  await loaded();
  expect(
    screen.queryByRole("button", { name: "Resolve incident", exact: true }),
  ).not.toBeInTheDocument();
  fireEvent.click(
    screen.getByRole("button", { name: "Start investigation", exact: true }),
  );
  fireEvent.click(
    screen.getByRole("button", { name: "Confirm start investigation" }),
  );
  fireEvent.click(
    await screen.findByRole("button", {
      name: "Resolve incident",
      exact: true,
    }),
  );
  expect(
    screen.getByRole("button", { name: "Confirm resolve incident" }),
  ).toBeDisabled();
  fireEvent.change(screen.getByLabelText("Resolution summary"), {
    target: { value: "Verified activity with owner." },
  });
  fireEvent.click(
    screen.getByRole("button", { name: "Confirm resolve incident" }),
  );
  expect(
    await screen.findByRole("button", { name: "Reopen incident", exact: true }),
  ).toBeVisible();
  expect(api.patch).toHaveBeenLastCalledWith("/incidents/INC-TEST-001/status", {
    status: "RESOLVED",
    resolution_summary: "Verified activity with owner.",
  });
});
it("requires a false-positive reason and confirms reopening", async () => {
  mount();
  await loaded();
  fireEvent.click(
    screen.getByRole("button", { name: "Mark false positive", exact: true }),
  );
  expect(
    screen.getByRole("button", { name: "Confirm mark false positive" }),
  ).toBeDisabled();
  fireEvent.change(screen.getByLabelText("False-positive reason"), {
    target: { value: "Approved security exercise." },
  });
  fireEvent.click(
    screen.getByRole("button", { name: "Confirm mark false positive" }),
  );
  fireEvent.click(
    await screen.findByRole("button", { name: "Reopen incident", exact: true }),
  );
  expect(api.patch).toHaveBeenCalledTimes(1);
  fireEvent.click(
    screen.getByRole("button", { name: "Confirm reopen incident" }),
  );
  expect(
    await screen.findByRole("button", {
      name: "Resolve incident",
      exact: true,
    }),
  ).toBeVisible();
  expect(api.patch).toHaveBeenCalledTimes(2);
});
it("keeps failed mutations visible without pretending success or logging out on 403", async () => {
  api.patch.mockRejectedValue({ response: { status: 403 } });
  mount();
  await loaded();
  fireEvent.click(
    screen.getByRole("button", { name: "Start investigation", exact: true }),
  );
  fireEvent.click(
    screen.getByRole("button", { name: "Confirm start investigation" }),
  );
  expect(
    await screen.findByText(/Your role does not have permission/),
  ).toBeVisible();
  expect(screen.getByRole("dialog")).toBeVisible();
  expect(incident.status).toBe("OPEN");
  expect(
    screen.queryByText("Incident status updated."),
  ).not.toBeInTheDocument();
});
it.each(["VIEWER", "ADMIN", "ANALYST"])(
  "enforces %s controls across investigation tabs",
  async (role) => {
    auth.user.role = role;
    mount();
    await loaded();
    if (role === "VIEWER")
      expect(
        screen.queryByRole("button", { name: "Assign", exact: true }),
      ).not.toBeInTheDocument();
    else
      expect(
        screen.getByRole("button", { name: "Assign", exact: true }),
      ).toBeVisible();
    await tab("Notes");
    await screen.findByText("Initial evidence review.");
    expect(Boolean(screen.queryByRole("button", { name: "Save note" }))).toBe(
      role !== "VIEWER",
    );
    await tab("Threat intel");
    await screen.findByText("Simulated intelligence");
    expect(
      Boolean(screen.queryByRole("button", { name: "Refresh intelligence" })),
    ).toBe(role !== "VIEWER");
  },
);
it("preserves queue filters on return and supports keyboard tabs", async () => {
  mount("?returnTo=%2Fincidents%3Fseverity%3DCRITICAL%26offset%3D20");
  await loaded();
  const overview = screen.getByRole("tab", { name: "Overview" });
  overview.focus();
  fireEvent.keyDown(overview, { key: "ArrowRight" });
  expect(screen.getByRole("tab", { name: "Timeline" })).toHaveFocus();
  expect(screen.getByRole("tab", { name: "Timeline" })).toHaveAttribute(
    "aria-selected",
    "true",
  );
  fireEvent.click(screen.getByRole("link", { name: "Back to incident queue" }));
  expect(await screen.findByLabelText("Severity")).toHaveValue("CRITICAL");
  await waitFor(() =>
    expect(api.get).toHaveBeenCalledWith(
      "/incidents",
      expect.objectContaining({
        params: { limit: 20, offset: 20, severity: "CRITICAL" },
      }),
    ),
  );
});
it("uses a safe queue destination for an untrusted returnTo query", async () => {
  mount("?returnTo=https%3A%2F%2Fevil.example");
  await loaded();
  expect(
    screen.getByRole("link", { name: "Back to incident queue" }),
  ).toHaveAttribute("href", "/incidents");
});
it("displays unavailable and changed risk honestly", async () => {
  incident.risk_score = 75;
  mount();
  await loaded();
  expect(screen.getByText(/Case risk remains 75/)).toBeVisible();
});
