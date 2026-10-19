import { Badge, Panel } from "../common/UI";
import { utc } from "../../utils/format";
import EvidenceLinks from "./EvidenceLinks";
export default function AnalysisReport({ analysis, incidentId }) {
  const evidence = (items) => (
    <ul className="ai-evidence-list">
      {items.map((item, i) => (
        <li key={i}>
          <p>{item.statement}</p>
          <EvidenceLinks
            ids={item.reference_ids}
            references={analysis.references}
            incidentId={incidentId}
          />
        </li>
      ))}
    </ul>
  );
  return (
    <div className="ai-report">
      <div className="ai-report-meta">
        <Badge tone={analysis.analysis_mode === "AI" ? "low" : "simulation"}>
          {analysis.analysis_mode === "AI"
            ? "AI GENERATED"
            : "DETERMINISTIC FALLBACK"}
        </Badge>
        <span>{utc(analysis.generated_at)}</span>
        <span>
          {analysis.provider}
          {analysis.model ? ` · ${analysis.model}` : ""}
        </span>
        <Badge>
          {analysis.stale
            ? "STALE"
            : analysis.is_current
              ? "CURRENT"
              : "PREVIOUS"}
        </Badge>
      </div>
      {analysis.stale && (
        <p className="ai-stale" role="status">
          Evidence or analyst configuration has changed, or the provider retry
          interval has elapsed. Regenerate analysis before relying on this
          version.
        </p>
      )}
      {analysis.fallback_reason && (
        <p className="info-note" role="status">
          The AI provider could not return validated analysis (
          {analysis.fallback_reason.replaceAll("_", " ")}). This report uses
          deterministic evidence explanations.
        </p>
      )}
      <Panel
        title="Incident summary"
        subtitle="Observed evidence and authoritative case state"
      >
        <div className="ai-prose">
          <p>{analysis.summary}</p>
          <h3>Why this was flagged</h3>
          <p>{analysis.why_flagged}</p>
        </div>
      </Panel>
      <div className="ai-report-grid">
        <Panel
          title="Key evidence"
          subtitle="Follow each reference to its source"
        >
          {evidence(analysis.key_evidence)}
        </Panel>
        <Panel
          title="Risk explanation"
          subtitle="Stored contributions · no AI recalculation"
        >
          {analysis.risk_explanation.length ? (
            evidence(analysis.risk_explanation)
          ) : (
            <p className="ai-prose">No current risk breakdown is available.</p>
          )}
        </Panel>
      </div>
      <div className="ai-report-grid">
        <Panel title="Investigation steps">
          <ol className="ai-action-list">
            {analysis.investigation_steps.map((s, i) => (
              <li key={i}>{s}</li>
            ))}
          </ol>
        </Panel>
        <Panel
          title="Recommended defensive actions"
          subtitle="Considerations for the analyst; no actions are executed"
        >
          <ol className="ai-action-list">
            {analysis.recommended_actions.map((s, i) => (
              <li key={i}>{s}</li>
            ))}
          </ol>
        </Panel>
      </div>
      <Panel title="Potential impact & uncertainty">
        <div className="ai-prose">
          <p>{analysis.potential_impact}</p>
          <p className="muted">{analysis.uncertainty}</p>
        </div>
      </Panel>
    </div>
  );
}
