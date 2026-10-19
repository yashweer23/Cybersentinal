import { useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { useMutation, useQuery } from "@tanstack/react-query";
import { ArrowUpRight, Search, Send } from "lucide-react";
import { useAuth } from "../context/AuthContext";
import { listIncidents } from "../services/incidentsApi";
import { askOverview } from "../services/aiApi";
import { useAIStatus } from "../hooks/useAI";
import {
  Badge,
  PageHeading,
  Panel,
  QueryState,
  ErrorState,
  Pagination,
  EmptyState,
} from "../components/common/UI";
import AIAnalysisPanel from "../components/ai/AIAnalysisPanel";
import "../ai.css";
const prompts = [
  "Summarize current critical incidents.",
  "Which detection rules generated the most incidents?",
  "What are the highest-risk open incidents?",
  "Which accounts have multiple suspicious findings?",
  "Summarize security activity from the last 24 hours.",
];
function SecurityOverview() {
  const { user } = useAuth();
  const status = useAIStatus();
  const [question, setQuestion] = useState("");
  const mutation = useMutation({ mutationFn: askOverview, retry: false });
  const enabled =
    ["ADMIN", "ANALYST"].includes(user.role) &&
    status.data?.enabled &&
    !status.isError;
  return (
    <Panel
      title="Security overview"
      subtitle="Five controlled read-only queries across retained CyberSentinel data"
    >
      <div className="ai-question-body">
        {user.role === "VIEWER" ? (
          <p className="info-note">
            Viewer access is limited to previously saved incident analyses.
          </p>
        ) : (
          <>
            <div className="ai-prompts">
              {prompts.map((p) => (
                <button
                  key={p}
                  className="button secondary small"
                  disabled={!enabled || mutation.isPending}
                  onClick={() => setQuestion(p)}
                >
                  {p}
                </button>
              ))}
            </div>
            <form
              className="ai-question-form"
              onSubmit={(e) => {
                e.preventDefault();
                if (
                  enabled &&
                  question.trim().length >= 3 &&
                  !mutation.isPending
                )
                  mutation.mutate(question.trim());
              }}
            >
              <label htmlFor="overview-question">Ask about security data</label>
              <textarea
                id="overview-question"
                placeholder="Summarize critical open incidents…"
                value={question}
                onChange={(e) => setQuestion(e.target.value)}
                minLength={3}
                maxLength={800}
                rows={3}
                disabled={!enabled || mutation.isPending}
              />
              <button
                className="button"
                disabled={
                  !enabled || mutation.isPending || question.trim().length < 3
                }
              >
                <Send size={15} />
                {mutation.isPending ? "Querying evidence…" : "Ask overview"}
              </button>
            </form>
          </>
        )}
        {status.isError && (
          <ErrorState error={status.error} retry={status.refetch} />
        )}
        {status.data && !status.data.enabled && (
          <p className="info-note">AI analyst is disabled.</p>
        )}
        {mutation.isError && <ErrorState error={mutation.error} />}
        {mutation.data && (
          <div className="ai-answer" role="status">
            <Badge>DETERMINISTIC FALLBACK</Badge>
            <h3>{mutation.data.answer}</h3>
            <p className="muted">{mutation.data.scope}</p>
            <ul className="ai-overview-evidence">
              {mutation.data.evidence.map((r, i) => (
                <li key={i}>
                  {r.incident_id ? (
                    <Link
                      className="panel-link"
                      to={`/incidents/${encodeURIComponent(r.incident_id)}?tab=ai-analysis`}
                    >
                      {r.incident_id}
                      <ArrowUpRight size={14} />
                    </Link>
                  ) : null}
                  <span>
                    {Object.entries(r)
                      .filter(([key]) => key !== "incident_id")
                      .map(
                        ([key, value]) =>
                          `${key.replaceAll("_", " ")}: ${value ?? "unknown"}`,
                      )
                      .join(" · ")}
                  </span>
                </li>
              ))}
            </ul>
            {mutation.data.truncated && (
              <p>
                Only the first 20 matches are shown. Use the incident queue for
                detailed filtering.
              </p>
            )}
            <p className="ai-disclaimer">{mutation.data.note}</p>
          </div>
        )}
      </div>
    </Panel>
  );
}
export default function AIAnalyst() {
  const [search, setSearch] = useSearchParams(),
    [offset, setOffset] = useState(0),
    [draft, setDraft] = useState("");
  const mode = search.get("mode") === "overview" ? "overview" : "incident";
  const selected = search.get("incident") || "";
  const query = useQuery({
    queryKey: ["ai-incident-picker", offset],
    queryFn: ({ signal }) => listIncidents({ limit: 10, offset }, signal),
    enabled: mode === "incident" && !selected,
  });
  const choose = (id) => setSearch({ mode: "incident", incident: id });
  return (
    <div className="ai-page">
      <PageHeading
        eyebrow="INVESTIGATION ASSISTANCE"
        title="AI security analyst"
        description="Source-linked explanations, stored risk context, and practical next steps."
      />
      <div className="ai-mode-switch" aria-label="Analyst mode">
        {[
          ["incident", "Incident analysis"],
          ["overview", "Security overview"],
        ].map(([value, label]) => (
          <button
            key={value}
            className={`button ${mode === value ? "" : "secondary"}`}
            aria-pressed={mode === value}
            onClick={() =>
              setSearch(
                value === "incident" && selected
                  ? { mode: value, incident: selected }
                  : { mode: value },
              )
            }
          >
            {label}
          </button>
        ))}
      </div>
      {mode === "overview" ? (
        <SecurityOverview />
      ) : (
        <>
          <form
            className="ai-select-form"
            onSubmit={(e) => {
              e.preventDefault();
              if (draft.trim()) choose(draft.trim());
            }}
          >
            <label htmlFor="ai-incident-id">Incident ID</label>
            <input
              id="ai-incident-id"
              maxLength={64}
              placeholder="INC-…"
              value={draft}
              onChange={(e) => setDraft(e.target.value)}
            />
            <button className="button secondary" disabled={!draft.trim()}>
              <Search size={16} />
              Open case
            </button>
            {selected && (
              <button
                type="button"
                className="text-button"
                onClick={() => setSearch({ mode: "incident" })}
              >
                Choose another incident
              </button>
            )}
          </form>
          {selected ? (
            <>
              <div className="ai-selected-case">
                <span className="mono">{selected}</span>
                <Link
                  className="panel-link"
                  to={`/incidents/${encodeURIComponent(selected)}?tab=ai-analysis`}
                >
                  Open investigation
                  <ArrowUpRight size={14} />
                </Link>
              </div>
              <AIAnalysisPanel key={selected} incidentId={selected} />
            </>
          ) : (
            <Panel
              title="Choose an incident"
              subtitle="Cases ordered by stored severity and risk"
            >
              <QueryState query={query}>
                {(data) => (
                  <>
                    {!data.items.length && (
                      <EmptyState
                        title="No incidents available"
                        description="Generate and process security events to create investigation cases."
                      />
                    )}
                    <div className="ai-case-picker">
                      {data.items.map((c) => (
                        <button
                          key={c.incident_id}
                          onClick={() => choose(c.incident_id)}
                        >
                          <div>
                            <span className="mono muted">{c.incident_id}</span>
                            <strong>{c.title}</strong>
                          </div>
                          <Badge tone={c.severity}>
                            {c.severity} · {c.risk_score}/100
                          </Badge>
                          <ArrowUpRight size={16} />
                        </button>
                      ))}
                    </div>
                    <Pagination
                      offset={offset}
                      limit={10}
                      total={data.total}
                      onChange={setOffset}
                    />
                  </>
                )}
              </QueryState>
            </Panel>
          )}
        </>
      )}
    </div>
  );
}
