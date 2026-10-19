import { Badge, EmptyState, RiskBadge, SeverityBadge } from "../common/UI";
import { utc } from "../../utils/format";
const components = [
  ["severity", "Detection severity"],
  ["confidence", "Detection confidence"],
  ["behavioural_intensity", "Behavioural intensity"],
  ["event_frequency", "Event frequency"],
  ["asset_sensitivity", "Asset sensitivity"],
  ["reputation", "Reputation"],
];
export default function RiskBreakdown({ assessment, incidentScore }) {
  if (!assessment)
    return (
      <EmptyState
        title="Risk breakdown unavailable"
        description="No assessment for this incident’s stored scoring version is available."
      />
    );
  const mismatch =
    incidentScore !== undefined && assessment.risk_score !== incidentScore;
  return (
    <div className="case-risk">
      <div className="case-risk-total">
        <div>
          <span className="eyebrow">STORED ASSESSMENT</span>
          <div>
            <RiskBadge value={assessment.risk_score} />
            <SeverityBadge value={assessment.risk_level} />
          </div>
        </div>
        <Badge>{assessment.score_version}</Badge>
      </div>
      {mismatch && (
        <p className="info-note" role="status">
          This finding assessment has changed since the case score was last
          updated. Case risk remains {incidentScore}/100 until incident
          processing runs again.
        </p>
      )}
      <p className="muted case-small">
        {assessment.finding_id} · {utc(assessment.calculated_at)}
      </p>
      {components.map(([key, title]) => {
        const item = assessment.breakdown[key];
        return (
          <div className="case-risk-component" key={key}>
            <div>
              <strong>{title}</strong>
              <span>
                {item.points} / {item.max}
              </span>
            </div>
            <progress value={item.points} max={item.max} aria-label={title} />
            <p>{item.reason}</p>
          </div>
        );
      })}
      <p className="case-small muted">
        The case uses the highest linked assessment for its stored scoring
        version. Component values and reasons come from the backend; detection
        confidence is a separate measure.
      </p>
    </div>
  );
}
