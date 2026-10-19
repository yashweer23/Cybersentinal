import { beforeEach, describe, expect, it, vi } from "vitest";
import {
  act,
  fireEvent,
  render,
  screen,
  waitFor,
  within,
} from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { api } from "../services/api";
import {
  DashboardProvider,
  readPreferences,
  shouldRetry,
  useDashboard,
} from "../context/DashboardContext";
import App from "../App";
import Overview from "../pages/Overview";
import Incidents, { incidentParams } from "../pages/Incidents";
import LiveEvents from "../pages/LiveEvents";
import DetectionRules from "../pages/DetectionRules";
import ThreatIntelligence, { Reputation } from "../pages/ThreatIntelligence";
import SystemHealth from "../pages/SystemHealth";
import { SeverityBadge, RiskBadge } from "../components/common/UI";
import { mergeEvents } from "../hooks/useLiveEvents";
import { dashboardGet } from "../services/dashboardApi";
import {
  dashboard,
  event,
  incident,
  providers,
  rule,
  threat,
} from "./fixtures";
const auth = vi.hoisted(() => ({
  user: {
    id: "user-1",
    username: "demoanalyst",
    full_name: "Demo Analyst",
    email: "analyst@example.test",
    role: "ANALYST",
  },
  status: "authenticated",
  signOut: vi.fn(),
  error: null,
}));
vi.mock("../context/AuthContext", () => ({ useAuth: () => auth }));
// Chart layout is verified in real Chromium; jsdom has no box layout.
vi.mock("../components/dashboard/Charts", () => ({
  SecurityTimeline: ({ data }) => <div>Timeline: {data.total}</div>,
  SeverityChart: ({ data }) => <div>Severity total: {data.total}</div>,
  DistributionBars: () => <div>Distribution chart</div>,
}));
function mount(element) {
  return render(
    <MemoryRouter>
      <DashboardProvider>{element}</DashboardProvider>
    </MemoryRouter>,
  );
}
function responses(url) {
  if (url.startsWith("/dashboard/"))
    return { data: structuredClone(dashboard[url.slice(11)]) };
  if (url === "/incidents")
    return { data: { items: [incident], total: 25, limit: 20, offset: 0 } };
  if (url === "/detection-rules") return { data: [rule] };
  if (url === "/threats/providers/status") return { data: providers };
  if (url === "/threats")
    return { data: { items: [threat], total: 1, limit: 10, offset: 0 } };
  throw new Error("Unexpected API request " + url);
}
beforeEach(() => {
  auth.user = { ...auth.user, id: "user-1", role: "ANALYST" };
  auth.status = "authenticated";
  vi.spyOn(api, "get").mockImplementation(async (url) => responses(url));
  vi.spyOn(api, "patch").mockResolvedValue({
    data: { rule_id: "CS-001", enabled: false },
  });
  vi.spyOn(api, "post").mockResolvedValue({ data: threat });
});
describe("SOC data and navigation", () => {
  it("renders server metrics, incidents, events and simulated reputation", async () => {
    mount(<Overview />);
    expect(
      screen.getAllByRole("status", { name: "Loading data" }).length,
    ).toBeGreaterThan(0);
    expect(await screen.findByText("1,240")).toBeVisible();
    expect(screen.getByText("Possible brute force activity")).toBeVisible();
    expect(screen.getByText("Simulated")).toBeVisible();
    expect(screen.getByRole("link", { name: /INC-TEST-001/ })).toHaveAttribute(
      "href",
      "/incidents/INC-TEST-001",
    );
    expect(api.get).toHaveBeenCalledWith(
      "/dashboard/overview",
      expect.objectContaining({ params: { range: "24h" } }),
    );
  });
  it("isolates component errors and supports retry", async () => {
    api.get.mockImplementation(async (url) => {
      if (url.endsWith("/events/timeline")) throw { response: { status: 403 } };
      return responses(url);
    });
    mount(<Overview />);
    expect(
      await screen.findByText(/Your role does not have permission/),
    ).toBeVisible();
    expect(screen.getByText("1,240")).toBeVisible();
    api.get.mockImplementation(async (url) => responses(url));
    fireEvent.click(screen.getByRole("button", { name: "Retry request" }));
    expect(await screen.findByText("Timeline: 5")).toBeVisible();
  });
  it("rejects malformed API payloads instead of fabricating zero metrics", async () => {
    api.get.mockResolvedValue({ data: { total_events: "unknown" } });
    await expect(dashboardGet("overview")).rejects.toThrow(
      "unexpected response",
    );
    mount(<Overview />);
    expect(
      (await screen.findAllByText(/unexpected response/)).length,
    ).toBeGreaterThan(0);
  });
  it("shows an intentional empty queue", async () => {
    api.get.mockResolvedValue({
      data: { items: [], total: 0, limit: 20, offset: 0 },
    });
    mount(<Incidents />);
    expect(await screen.findByText("No matching records")).toBeVisible();
    expect(screen.getByText(/0 results/)).toBeVisible();
  });
  it("updates range queries and preserves selection across sidebar navigation", async () => {
    render(
      <MemoryRouter>
        <App />
      </MemoryRouter>,
    );
    await screen.findByText("1,240");
    fireEvent.change(screen.getByLabelText("Time range"), {
      target: { value: "7d" },
    });
    await waitFor(() =>
      expect(api.get).toHaveBeenCalledWith(
        "/dashboard/overview",
        expect.objectContaining({ params: { range: "7d" } }),
      ),
    );
    fireEvent.click(
      screen.getByRole("link", { name: "Analytics", exact: true }),
    );
    await screen.findByRole("heading", { name: "Advanced security analytics" });
    expect(
      screen.getByRole("button", { name: "7D", exact: true }),
    ).toHaveAttribute("aria-pressed", "true");
    fireEvent.click(
      screen.getByRole("link", { name: "Settings", exact: true }),
    );
    expect(await screen.findByText("Browser-local preferences")).toBeVisible();
  });
  it("replaces cached security data when the authenticated identity changes", async () => {
    const view = mount(<Overview />);
    await screen.findByText("1,240");
    auth.user = { ...auth.user, id: "user-2", role: "VIEWER" };
    api.get.mockImplementation(async (url) => {
      const result = responses(url);
      if (url === "/dashboard/overview") result.data.events_in_range = 17;
      return result;
    });
    view.rerender(
      <MemoryRouter>
        <DashboardProvider>
          <Overview />
        </DashboardProvider>
      </MemoryRouter>,
    );
    await screen.findByText("17");
    expect(screen.queryByText("1,240")).not.toBeInTheDocument();
  });
  it("uses backend incident filters and pagination", async () => {
    mount(<Incidents />);
    await screen.findByText("Possible brute force activity");
    fireEvent.change(screen.getByLabelText("Severity"), {
      target: { value: "CRITICAL" },
    });
    fireEvent.change(screen.getByLabelText("Minimum risk"), {
      target: { value: "75" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Apply filters" }));
    await waitFor(() =>
      expect(api.get).toHaveBeenCalledWith(
        "/incidents",
        expect.objectContaining({
          params: {
            limit: 20,
            offset: 0,
            severity: "CRITICAL",
            minimum_risk: "75",
          },
        }),
      ),
    );
    fireEvent.click(await screen.findByRole("button", { name: "Next" }));
    await waitFor(() =>
      expect(api.get).toHaveBeenCalledWith(
        "/incidents",
        expect.objectContaining({
          params: {
            limit: 20,
            offset: 20,
            severity: "CRITICAL",
            minimum_risk: "75",
          },
        }),
      ),
    );
  });
  it("serializes incident date inputs explicitly as UTC", () => {
    expect(
      incidentParams({ start_time: "2026-10-10T09:15", end_time: "" }, 0),
    ).toEqual({ limit: 20, offset: 0, start_time: "2026-10-10T09:15:00Z" });
  });
  it("shows text labels for severity and numeric risk", () => {
    mount(
      <>
        <SeverityBadge value="CRITICAL" />
        <RiskBadge value={87} />
        <RiskBadge value={null} />
      </>,
    );
    expect(screen.getByText("Critical")).toBeVisible();
    expect(screen.getByText("87")).toBeVisible();
    expect(screen.getByText("/100")).toBeVisible();
    expect(screen.getByText("—")).toBeVisible();
  });
  it("keeps preferences account-scoped and handles invalid storage", () => {
    localStorage.setItem("prefs", "broken");
    expect(readPreferences("prefs").defaultRange).toBe("24h");
    localStorage.setItem(
      "prefs",
      JSON.stringify({ defaultRange: "bogus", autoRefresh: false }),
    );
    expect(readPreferences("prefs")).toEqual({
      defaultRange: "24h",
      autoRefresh: false,
      collapsed: false,
    });
  });
  it("does not retry permanent authorization or input errors", () => {
    for (const status of [401, 403, 404, 422])
      expect(shouldRetry(0, { response: { status } })).toBe(false);
    expect(shouldRetry(0, new Error("network"))).toBe(true);
    expect(shouldRetry(1, new Error("network"))).toBe(false);
  });
});
describe("permissions and truthful health", () => {
  it.each(["VIEWER", "ANALYST"])("%s cannot edit rules", async (role) => {
    auth.user.role = role;
    mount(<DetectionRules />);
    await screen.findByText("Brute Force Detection");
    expect(screen.queryByRole("switch")).not.toBeInTheDocument();
  });
  it("ADMIN can toggle an actual rule and sends only enabled", async () => {
    auth.user.role = "ADMIN";
    mount(<DetectionRules />);
    fireEvent.click(
      await screen.findByRole("switch", { name: "Disable CS-001" }),
    );
    await waitFor(() =>
      expect(api.patch).toHaveBeenCalledWith("/detection-rules/CS-001", {
        enabled: false,
      }),
    );
  });
  it("VIEWER can inspect cache but cannot trigger lookup", async () => {
    auth.user.role = "VIEWER";
    mount(<ThreatIntelligence />);
    await screen.findByText("198.51.100.73");
    expect(
      screen.queryByRole("button", { name: "Run lookup" }),
    ).not.toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "198.51.100.73" }));
    expect(await screen.findByText("Indicator · 198.51.100.73")).toBeVisible();
    expect(api.post).not.toHaveBeenCalled();
  });
  it.each(["ANALYST", "ADMIN"])(
    "%s can explicitly look up an IP",
    async (role) => {
      auth.user.role = role;
      mount(<ThreatIntelligence />);
      await screen.findByText("Cached intelligence");
      fireEvent.change(screen.getByLabelText("IP address"), {
        target: { value: "192.0.2.44" },
      });
      fireEvent.click(screen.getByRole("button", { name: "Run lookup" }));
      await waitFor(() =>
        expect(api.post).toHaveBeenCalledWith("/threats/lookup", {
          ip: "192.0.2.44",
          force_refresh: false,
        }),
      );
    },
  );
  it("marks expired reputation unknown", () => {
    mount(<Reputation result={{ ...threat, stale: true }} />);
    expect(screen.getByText("Unknown")).toBeVisible();
    expect(screen.queryByText("Malicious")).not.toBeInTheDocument();
  });
  it("removes healthy cards after a failed health refresh", async () => {
    function HealthWithRefresh() {
      const { refresh } = useDashboard();
      return (
        <>
          <button onClick={refresh}>Refresh health</button>
          <SystemHealth />
        </>
      );
    }
    mount(<HealthWithRefresh />);
    await screen.findByText("FastAPI");
    api.get.mockRejectedValue({ response: { status: 403 } });
    fireEvent.click(screen.getByRole("button", { name: "Refresh health" }));
    await screen.findByText(/Your role does not have permission/);
    expect(screen.queryByText("FastAPI")).not.toBeInTheDocument();
    expect(screen.queryByText("Healthy")).not.toBeInTheDocument();
  });
});
describe("bounded cursor feed", () => {
  it("deduplicates UUIDs and compares large decimal cursors without precision loss", () => {
    const rows = mergeEvents(
      [event("a", "9007199254740992")],
      [event("a", "9007199254740992"), event("b", "9007199254740993")],
    );
    expect(rows.map((r) => r.id)).toEqual(["b", "a"]);
    expect(
      mergeEvents(
        [],
        Array.from({ length: 800 }, (_, i) => event(String(i), String(i))),
      ).length,
    ).toBe(500);
  });
  it("polls by cursor, drains has_more, keeps late events and clears only local state", async () => {
    vi.useFakeTimers();
    let updates = 0;
    api.get.mockImplementation(async (url, config) => {
      if (url.endsWith("/events/recent")) return responses(url);
      expect(config.params.after_id).toBe(updates === 0 ? "1" : "2");
      updates++;
      return {
        data: {
          items:
            updates === 1
              ? [event("2", "2"), event()]
              : [{ ...event("3", "3"), timestamp: "2026-01-01T00:00:00Z" }],
          next_cursor: updates === 1 ? "2" : "3",
          head_cursor: "3",
          has_more: updates === 1,
        },
      };
    });
    mount(<LiveEvents />);
    await act(async () => {});
    expect(screen.getByText("1 visible / 1 retained")).toBeVisible();
    await act(async () => {
      await vi.advanceTimersByTimeAsync(5000);
    });
    await act(async () => {
      await vi.advanceTimersByTimeAsync(100);
    });
    expect(screen.getByText("3 visible / 3 retained")).toBeVisible();
    fireEvent.click(screen.getByRole("button", { name: "Clear display" }));
    expect(screen.getByText("0 visible / 0 retained")).toBeVisible();
    expect(api.post).not.toHaveBeenCalled();
  });
  it("pauses without fetching, resumes from the cursor and stops while hidden", async () => {
    vi.useFakeTimers();
    mount(<LiveEvents />);
    await act(async () => {});
    const calls = api.get.mock.calls.length;
    fireEvent.click(screen.getByRole("button", { name: "Pause" }));
    await act(async () => {
      await vi.advanceTimersByTimeAsync(20000);
    });
    expect(api.get.mock.calls.length).toBe(calls);
    fireEvent.click(screen.getByRole("button", { name: "Resume" }));
    await act(async () => {});
    expect(api.get.mock.calls.length).toBe(calls + 1);
    const hidden = vi.spyOn(document, "hidden", "get").mockReturnValue(true);
    fireEvent(document, new Event("visibilitychange"));
    await act(async () => {
      await vi.advanceTimersByTimeAsync(20000);
    });
    expect(api.get.mock.calls.length).toBe(calls + 1);
    hidden.mockReturnValue(false);
    fireEvent(document, new Event("visibilitychange"));
    await act(async () => {});
    expect(api.get.mock.calls.length).toBe(calls + 2);
  });
  it("aborts the polling request on unmount", async () => {
    let signal;
    api.get.mockImplementation((url, options) => {
      signal = options.signal;
      return new Promise(() => {});
    });
    const view = mount(<LiveEvents />);
    view.unmount();
    expect(signal.aborted).toBe(true);
  });
});
