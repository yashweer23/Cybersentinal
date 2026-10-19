import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Bot, History, RefreshCw, Sparkles } from "lucide-react";
import { useAuth } from "../../context/AuthContext";
import {
  useAnalysis,
  useAIStatus,
  useGenerateAnalysis,
} from "../../hooks/useAI";
import { analysisHistory } from "../../services/aiApi";
import {
  Badge,
  EmptyState,
  ErrorState,
  Pagination,
  Panel,
  QueryState,
} from "../common/UI";
import { utc } from "../../utils/format";
import AnalysisReport from "./AnalysisReport";
import IncidentQuestions from "./IncidentQuestions";
import "../../ai.css";
function HistoryPanel({ id }) {
  const [offset, setOffset] = useState(0),
    [expanded, setExpanded] = useState(null);
  const query = useQuery({
    queryKey: ["ai", id, "history", offset],
    queryFn: ({ signal }) => analysisHistory(id, offset, signal),
  });
  return (
    <Panel
      title="Analysis history"
      subtitle="Saved versions are retained; current means latest and evidence-compatible"
    >
      <QueryState query={query}>
        {(data) => (
          <>
            <div className="ai-history">
              {data.items.map((a) => (
                <article key={a.analysis_id}>
                  <div>
                    <strong>{utc(a.generated_at)}</strong>
                    <Badge>{a.analysis_mode}</Badge>
                    <Badge>
                      {a.stale
                        ? "STALE"
                        : a.is_current
                          ? "CURRENT"
                          : "PREVIOUS"}
                    </Badge>
                  </div>
                  <p className="muted">
                    Requested by {a.generated_by_user_id || "system"} ·{" "}
                    {a.provider}
                    {a.model ? ` / ${a.model}` : ""}
                  </p>
                  <button
                    className="text-button"
                    onClick={() =>
                      setExpanded(
                        expanded === a.analysis_id ? null : a.analysis_id,
                      )
                    }
                    aria-expanded={expanded === a.analysis_id}
                  >
                    {expanded === a.analysis_id
                      ? "Hide saved report"
                      : "View saved report"}
                  </button>
                  {expanded === a.analysis_id && (
                    <AnalysisReport analysis={a} incidentId={id} />
                  )}
                </article>
              ))}
            </div>
            <Pagination
              offset={offset}
              limit={5}
              total={data.total}
              onChange={(value) => {
                setOffset(value);
                setExpanded(null);
              }}
            />
          </>
        )}
      </QueryState>
    </Panel>
  );
}
export default function AIAnalysisPanel({ incidentId }) {
  const { user } = useAuth();
  const query = useAnalysis(incidentId),
    status = useAIStatus(),
    generate = useGenerateAnalysis(incidentId);
  const [history, setHistory] = useState(false);
  const canWrite = ["ADMIN", "ANALYST"].includes(user.role);
  const enabled = canWrite && status.data?.enabled && !status.isError;
  const analysis = query.data?.analysis;
  return (
    <div className="ai-workspace">
      <div className="ai-toolbar">
        <div className="ai-title">
          <span className="ai-icon">
            <Bot size={22} />
          </span>
          <div>
            <h2>Evidence-grounded analyst</h2>
            <p>Explain the case. Keep the evidence in view.</p>
          </div>
        </div>
        <div className="case-actions">
          {status.data && (
            <Badge tone={status.data.mode === "AI" ? "low" : "neutral"}>
              {status.data.status}
            </Badge>
          )}
          {canWrite && (
            <button
              className="button"
              onClick={() => generate.mutate(Boolean(analysis))}
              disabled={
                !enabled ||
                generate.isPending ||
                query.isPending ||
                query.isError
              }
            >
              <Sparkles size={16} />
              {generate.isPending
                ? "Analyzing evidence…"
                : analysis
                  ? "Regenerate analysis"
                  : "Analyze incident"}
            </button>
          )}
          <button
            className="button secondary small"
            onClick={() => {
              void query.refetch();
            }}
            disabled={query.isFetching || generate.isPending}
          >
            <RefreshCw size={14} />
            Check freshness
          </button>
          <button
            className="button secondary small"
            onClick={() => setHistory(!history)}
            aria-expanded={history}
          >
            <History size={15} />
            {history ? "Hide history" : "Analysis history"}
          </button>
        </div>
      </div>
      {status.isError && (
        <ErrorState error={status.error} retry={status.refetch} />
      )}
      {status.data && !status.data.enabled && (
        <p className="info-note">
          Analysis generation is disabled. Previously saved reports remain
          available.
        </p>
      )}
      {!canWrite && (
        <p className="info-note">
          Viewer access · You can read saved analysis and history. An analyst or
          administrator must generate reports or ask questions.
        </p>
      )}
      {generate.isError && <ErrorState error={generate.error} />}
      {generate.isPending && (
        <p className="info-note" role="status">
          Building bounded context and validating evidence. No incident or
          security settings will be changed.
        </p>
      )}
      <QueryState query={query}>
        {(data) =>
          data.analysis ? (
            <AnalysisReport analysis={data.analysis} incidentId={incidentId} />
          ) : (
            <EmptyState
              title="No analysis generated yet"
              description={
                canWrite
                  ? "Analyze this incident to get a source-linked explanation and investigation guidance."
                  : "Ask an analyst to generate a report for this incident."
              }
            />
          )
        }
      </QueryState>
      {history && <HistoryPanel id={incidentId} />}
      {canWrite && (
        <IncidentQuestions
          key={incidentId}
          incidentId={incidentId}
          enabled={enabled}
        />
      )}
      <p className="ai-disclaimer">
        Analysis assists investigation and may be incomplete. Verify conclusions
        against the linked security evidence. Detection, scoring, and case
        decisions remain authoritative.
      </p>
    </div>
  );
}
