import { useState } from "react";
import { ChartNoAxesCombined, CalendarRange } from "lucide-react";
import { Badge, PageHeading } from "../components/common/UI";
import { ANALYTICS_PERIODS, useAnalyticsPeriod } from "../hooks/useAnalytics";
import {
  Executive,
  ThreatTrends,
  DetectionPerformance,
  IncidentPerformance,
  RiskAnalytics,
  IntelligenceAnalytics,
  AnalystOperations,
} from "../components/analytics/AnalyticsSections";
import ReportPanel from "../components/analytics/ReportPanel";
import { utc } from "../utils/format";
import "../analytics.css";
const tabs = [
  ["executive", "Executive overview"],
  ["trends", "Threat trends"],
  ["detections", "Detection performance"],
  ["incidents", "Incident performance"],
  ["risk", "Risk & entities"],
  ["intelligence", "Threat intelligence"],
  ["operations", "Analyst operations"],
  ["reports", "Reports"],
];
const components = {
  executive: Executive,
  trends: ThreatTrends,
  detections: DetectionPerformance,
  incidents: IncidentPerformance,
  risk: RiskAnalytics,
  intelligence: IntelligenceAnalytics,
  operations: AnalystOperations,
  reports: ReportPanel,
};
export default function Analytics() {
  const period = useAnalyticsPeriod();
  const [custom, setCustom] = useState(false),
    [draft, setDraft] = useState({ start: "", end: "" }),
    [error, setError] = useState("");
  const selected = components[period.section] ? period.section : "executive";
  const Section = components[selected];
  function applyCustom(e) {
    e.preventDefault();
    const a = new Date(draft.start + "Z"),
      b = new Date(draft.end + "Z");
    if (
      !Number.isFinite(+a) ||
      !Number.isFinite(+b) ||
      b <= a ||
      b - a > 90 * 86400000
    ) {
      setError("Choose an ordered UTC range of at most 90 days.");
      return;
    }
    setError("");
    period.update({
      period: "custom",
      start: a.toISOString(),
      end: b.toISOString(),
    });
    setCustom(false);
  }
  return (
    <div className="analytics-workspace">
      <PageHeading
        eyebrow="SECURITY INTELLIGENCE"
        title="Advanced security analytics"
        description="Understand threat patterns, response workload and the evidence behind every metric."
      >
        <Badge>
          <ChartNoAxesCombined size={13} /> OBSERVED DATA
        </Badge>
      </PageHeading>
      <section className="analytics-toolbar" aria-label="Analytics period">
        <div className="analytics-periods">
          {ANALYTICS_PERIODS.map((p) => (
            <button
              key={p}
              className={period.preset === p ? "selected" : ""}
              aria-pressed={period.preset === p}
              onClick={() => {
                period.update({ period: p, start: null, end: null });
                setCustom(false);
                setError("");
              }}
            >
              {p.toUpperCase()}
            </button>
          ))}
          <button
            className={period.preset === "custom" ? "selected" : ""}
            onClick={() => {
              setDraft({
                start: period.params?.start.slice(0, 16) || "",
                end: period.params?.end.slice(0, 16) || "",
              });
              setCustom(!custom);
            }}
            aria-expanded={custom}
          >
            <CalendarRange size={14} />
            Custom range
          </button>
        </div>
        <span className="analytics-utc">UTC · end exclusive</span>
      </section>
      {custom && (
        <form className="analytics-custom" onSubmit={applyCustom}>
          <label>
            Start (UTC)
            <input
              type="datetime-local"
              required
              value={draft.start}
              onChange={(e) => setDraft({ ...draft, start: e.target.value })}
            />
          </label>
          <label>
            End (UTC)
            <input
              type="datetime-local"
              required
              value={draft.end}
              onChange={(e) => setDraft({ ...draft, end: e.target.value })}
            />
          </label>
          <button className="button primary">Apply custom range</button>
        </form>
      )}
      {(error || period.error) && (
        <div className="soc-error" role="alert">
          {error || period.error}
        </div>
      )}
      {period.params && (
        <p className="analytics-period-caption">
          {utc(period.params.start)} <span>→</span> {utc(period.params.end)}
          <small>
            {" "}
            One period across all sections · refresh to advance a rolling range
          </small>
        </p>
      )}
      <div
        className="analytics-tabs"
        role="tablist"
        aria-label="Analytics sections"
        onKeyDown={(e) => {
          if (!["ArrowLeft", "ArrowRight", "Home", "End"].includes(e.key))
            return;
          e.preventDefault();
          const index = tabs.findIndex(([key]) => key === selected);
          const next =
            e.key === "Home"
              ? 0
              : e.key === "End"
                ? tabs.length - 1
                : (index + (e.key === "ArrowRight" ? 1 : -1) + tabs.length) %
                  tabs.length;
          period.update({ section: tabs[next][0] });
          e.currentTarget.querySelectorAll("button")[next].focus();
        }}
      >
        {tabs.map(([key, title]) => (
          <button
            key={key}
            id={`analytics-tab-${key}`}
            role="tab"
            aria-selected={selected === key}
            aria-controls="analytics-panel"
            tabIndex={selected === key ? 0 : -1}
            onClick={() => period.update({ section: key })}
          >
            {title}
          </button>
        ))}
      </div>
      {!period.error && (
        <div
          id="analytics-panel"
          role="tabpanel"
          aria-labelledby={`analytics-tab-${selected}`}
        >
          <Section
            key={
              selected === "reports" ? JSON.stringify(period.params) : selected
            }
            period={period}
          />
        </div>
      )}
      <p className="analytics-boundary-note">
        Read-only analytics · current states and scores · synthetic evaluation
        is labelled separately · no automated security actions
      </p>
    </div>
  );
}
