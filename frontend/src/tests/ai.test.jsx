import {
  fireEvent,
  render,
  screen,
  waitFor,
  within,
} from "@testing-library/react";
import { beforeEach, expect, it, vi } from "vitest";
import { MemoryRouter } from "react-router-dom";
import { DashboardProvider } from "../context/DashboardContext";
import { api } from "../services/api";
import AIAnalysisPanel from "../components/ai/AIAnalysisPanel";
import AIAnalyst from "../pages/AIAnalyst";
import { validateAnalysis } from "../services/aiApi";
const auth = vi.hoisted(() => ({
  user: { id: "analyst-1", username: "analyst", role: "ANALYST" },
}));
vi.mock("../context/AuthContext", () => ({ useAuth: () => auth }));
const report = {
  analysis_id: "AI-1",
  incident_id: "INC-1",
  analysis_mode: "FALLBACK",
  summary: "Stored risk is 88/100.",
  why_flagged: "CS-001: 18 failures, threshold 7.",
  potential_impact: "Unauthorized access could affect the account.",
  uncertainty: "Suspicious activity does not prove compromise.",
  generated_at: "2026-10-12T12:00:00Z",
  is_current: true,
  stale: false,
  cached: false,
  provider: "deterministic",
  model: null,
  generated_by_user_id: "analyst-1",
  coverage: { events_total: 18, events_included: 18 },
  investigation_steps: ["Verify account activity."],
  recommended_actions: ["Review MFA."],
  risk_explanation: [],
  key_evidence: [
    { statement: "18 failures observed.", reference_ids: ["FIND-1"] },
  ],
  references: [{ reference_id: "FIND-1", kind: "finding", label: "Finding 1" }],
  fallback_reason: null,
};
let current, history;
function mount(component = <AIAnalysisPanel incidentId="INC-1" />) {
  return render(
    <MemoryRouter>
      <DashboardProvider>{component}</DashboardProvider>
    </MemoryRouter>,
  );
}
beforeEach(() => {
  auth.user.role = "ANALYST";
  current = null;
  history = [];
  vi.spyOn(api, "get").mockImplementation(async (url) => {
    if (url === "/ai/status")
      return {
        data: {
          enabled: true,
          configured: false,
          mode: "FALLBACK",
          status: "FALLBACK",
          provider: "deterministic",
          note: "No provider configured.",
        },
      };
    if (url.endsWith("/analysis")) return { data: { analysis: current } };
    if (url.endsWith("/history"))
      return {
        data: { items: history, total: history.length, offset: 0, limit: 5 },
      };
    if (url === "/detections/FIND-1")
      return {
        data: {
          finding_id: "FIND-1",
          description: "Original detection evidence",
          evidence_data: { attempt_count: 18, threshold: 7 },
          evidence_event_ids: ["EVT-1"],
          event_count: 18,
        },
      };
    if (url === "/incidents")
      return { data: { items: [], total: 0, offset: 0, limit: 10 } };
    throw new Error("Unexpected GET " + url);
  });
  vi.spyOn(api, "post").mockImplementation(async (url, body) => {
    if (url.endsWith("/analyze")) {
      current = {
        ...report,
        analysis_id: body.force_refresh ? "AI-2" : "AI-1",
      };
      history.unshift(current);
      return { data: current };
    }
    if (url.endsWith("/ask"))
      return {
        data: {
          answer: "Available evidence does not establish this.",
          evidence_ids: ["FIND-1"],
          references: report.references,
          analysis_mode: "FALLBACK",
          confidence: "INSUFFICIENT",
          uncertainty: "Review full evidence.",
          context_hash: "hash",
        },
      };
    throw new Error("Unexpected POST " + url);
  });
});
it("shows empty state and never generates on page load", async () => {
  mount();
  await screen.findByText("No analysis generated yet");
  expect(api.post).not.toHaveBeenCalled();
  expect(
    screen.getByRole("button", { name: "Analyze incident" }),
  ).toBeEnabled();
});
it("generates labelled fallback and opens original evidence in a drawer", async () => {
  mount();
  await screen.findByText("No analysis generated yet");
  await waitFor(() =>
    expect(
      screen.getByRole("button", { name: "Analyze incident" }),
    ).toBeEnabled(),
  );
  fireEvent.click(screen.getByRole("button", { name: "Analyze incident" }));
  await screen.findByText("Stored risk is 88/100.");
  expect(screen.getByText("DETERMINISTIC FALLBACK")).toBeInTheDocument();
  fireEvent.click(screen.getByRole("button", { name: "View evidence FIND-1" }));
  const dialog = await screen.findByRole("dialog");
  expect(
    await within(dialog).findByText("Original detection evidence"),
  ).toBeInTheDocument();
});
it("shows pending state and suppresses duplicate generation", async () => {
  let finish;
  api.post.mockImplementationOnce(
    () =>
      new Promise((resolve) => {
        finish = resolve;
      }),
  );
  mount();
  await screen.findByText("No analysis generated yet");
  fireEvent.click(screen.getByRole("button", { name: "Analyze incident" }));
  expect(
    await screen.findByRole("button", { name: "Analyzing evidence…" }),
  ).toBeDisabled();
  finish({ data: report });
  await screen.findByText("Stored risk is 88/100.");
  expect(api.post).toHaveBeenCalledTimes(1);
});
it("shows stale state and explicitly regenerates while preserving history", async () => {
  current = { ...report, is_current: false, stale: true };
  history = [current];
  mount();
  await screen.findByText(/Evidence or analyst configuration has changed/);
  fireEvent.click(screen.getByRole("button", { name: "Regenerate analysis" }));
  await waitFor(() =>
    expect(api.post).toHaveBeenCalledWith(
      "/ai/incidents/INC-1/analyze",
      { force_refresh: true },
      { timeout: 90000 },
    ),
  );
  await waitFor(() =>
    expect(
      screen.queryByText(/Evidence or analyst configuration has changed/),
    ).not.toBeInTheDocument(),
  );
  fireEvent.click(screen.getByRole("button", { name: "Analysis history" }));
  await screen.findByText(
    "Saved versions are retained; current means latest and evidence-compatible",
  );
  expect(await screen.findAllByText("View saved report")).toHaveLength(2);
});
it("asks scoped questions and renders reference-backed text safely", async () => {
  mount();
  await screen.findByText("No analysis generated yet");
  fireEvent.click(
    screen.getByRole("button", {
      name: "Was there a successful login after failures?",
    }),
  );
  fireEvent.click(screen.getByRole("button", { name: "Ask question" }));
  expect(
    await screen.findByText("Available evidence does not establish this."),
  ).toBeInTheDocument();
  expect(
    screen.getByRole("button", { name: "View evidence FIND-1" }),
  ).toBeInTheDocument();
  expect(api.post).toHaveBeenCalledWith(
    "/ai/incidents/INC-1/ask",
    { question: "Was there a successful login after failures?" },
    { timeout: 90000 },
  );
});
it("displays generation errors without hiding saved evidence", async () => {
  current = report;
  api.post.mockRejectedValueOnce({
    response: { status: 503, data: { detail: "Database unavailable" } },
  });
  mount();
  fireEvent.click(
    await screen.findByRole("button", { name: "Regenerate analysis" }),
  );
  expect(await screen.findByText("Database unavailable")).toBeInTheDocument();
  expect(screen.getByText("Stored risk is 88/100.")).toBeInTheDocument();
});
it("shows provider failure fallback and AI-generated labels accurately", async () => {
  current = { ...report, fallback_reason: "rate_limited" };
  const view = mount();
  expect(
    await screen.findByText(/could not return validated analysis/),
  ).toBeInTheDocument();
  view.unmount();
  current = {
    ...report,
    analysis_mode: "AI",
    provider: "openai",
    model: "test-model",
  };
  mount();
  expect(await screen.findByText("AI GENERATED")).toBeInTheDocument();
  expect(screen.queryByText("DETERMINISTIC FALLBACK")).not.toBeInTheDocument();
});
it("viewer can read saved report and history but cannot generate or ask", async () => {
  auth.user.role = "VIEWER";
  current = report;
  history = [report];
  mount();
  await screen.findByText("Stored risk is 88/100.");
  expect(
    screen.queryByRole("button", { name: "Regenerate analysis" }),
  ).not.toBeInTheDocument();
  expect(
    screen.queryByRole("button", { name: "Ask question" }),
  ).not.toBeInTheDocument();
  fireEvent.click(screen.getByRole("button", { name: "Analysis history" }));
  expect(await screen.findByText("View saved report")).toBeInTheDocument();
  expect(api.post).not.toHaveBeenCalled();
});
it("analyst page offers incident selection and controlled security overview", async () => {
  mount(<AIAnalyst />);
  await screen.findByText("No incidents available");
  fireEvent.click(screen.getByRole("button", { name: "Security overview" }));
  await waitFor(() =>
    expect(
      screen.getByRole("button", {
        name: "Summarize current critical incidents.",
      }),
    ).toBeEnabled(),
  );
  fireEvent.click(
    screen.getByRole("button", {
      name: "Summarize current critical incidents.",
    }),
  );
  api.post.mockResolvedValueOnce({
    data: {
      answer: "2 critical incidents.",
      evidence: [{ incident_id: "INC-1", risk_score: 88, status: "OPEN" }],
      scope: "Current active cases",
      analysis_mode: "FALLBACK",
      note: "Controlled query.",
      total: 2,
      truncated: false,
    },
  });
  await waitFor(() =>
    expect(screen.getByRole("button", { name: "Ask overview" })).toBeEnabled(),
  );
  fireEvent.click(screen.getByRole("button", { name: "Ask overview" }));
  expect(await screen.findByText("2 critical incidents.")).toBeInTheDocument();
  expect(screen.getByRole("link", { name: "INC-1" })).toHaveAttribute(
    "href",
    "/incidents/INC-1?tab=ai-analysis",
  );
});
it("rejects a response with unsupported evidence references at the UI boundary", () => {
  expect(() => validateAnalysis({ ...report, references: [] })).toThrow(
    /unexpected response/,
  );
});
