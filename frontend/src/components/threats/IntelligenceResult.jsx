import { Badge, DataTable, Panel, Time } from "../common/UI";
import { label, number } from "../../utils/format";
export const staleResult = (result) =>
  result.stale ||
  result.configuration_changed ||
  Date.parse(result.expires_at) <= Date.now();
export function Reputation({ result }) {
  const stale = staleResult(result);
  const level = stale ? "UNKNOWN" : result.reputation_level;
  return (
    <div className="cell-stack">
      <Badge
        tone={
          level === "MALICIOUS"
            ? "critical"
            : level === "SUSPICIOUS"
              ? "high"
              : "neutral"
        }
      >
        {label(level)}
      </Badge>
      {stale && (
        <small className="text-high">
          {result.configuration_changed
            ? "Configuration changed"
            : "Expired cache"}
        </small>
      )}
    </div>
  );
}
export function IntelligenceDetail({ result, close }) {
  return (
    <Panel
      title={`Indicator · ${result.indicator}`}
      subtitle="Stored or explicitly requested intelligence"
      action={
        <button className="button secondary small" onClick={close}>
          Close details
        </button>
      }
    >
      <div className="detail-content">
        <div className="inline-badges">
          <Reputation result={result} />
          <Badge tone={result.simulation ? "simulation" : "neutral"}>
            {result.simulation
              ? "Simulated intelligence"
              : "Live provider data"}
          </Badge>
          <span>
            Normalized score:{" "}
            <strong>
              {staleResult(result)
                ? "Unknown"
                : number(result.normalized_score)}
            </strong>
          </span>
          <Badge>{label(result.lookup_status)}</Badge>
        </div>
        <p>{result.explanation}</p>
        <p className="muted">
          Checked <Time value={result.checked_at} /> · Expires{" "}
          <Time value={result.expires_at} />
        </p>
      </div>
      <DataTable
        caption="Intelligence provider results"
        rowKey="provider"
        rows={result.providers}
        columns={[
          { key: "provider", title: "Provider" },
          {
            key: "lookup_status",
            title: "Result",
            render: (r) => label(r.lookup_status),
          },
          {
            key: "normalized_score",
            title: "Stored score",
            render: (r) => number(r.normalized_score),
          },
          {
            key: "reports",
            title: "Reports",
            render: (r) => number(r.reports),
          },
          { key: "country", title: "Country" },
          { key: "isp", title: "ISP" },
          {
            key: "explanation",
            title: "Context",
            render: (r) => (
              <span className="wrapped-cell">{r.explanation}</span>
            ),
          },
        ]}
      />
      <div className="panel-footnote">
        Provider rows show the stored observation. Expired or incompatible
        results are not a current reputation verdict. Unknown is not safe.
      </div>
    </Panel>
  );
}
