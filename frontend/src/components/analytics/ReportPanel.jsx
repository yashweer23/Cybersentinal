import { useEffect, useRef, useState } from "react";
import { Download, FileText } from "lucide-react";
import { useAuth } from "../../context/AuthContext";
import { Panel, Badge } from "../common/UI";
import { downloadReport } from "../../services/analyticsApi";
import { utc } from "../../utils/format";
const types = [
  ["security-summary", "Executive security summary"],
  ["incidents", "Incidents"],
  ["detection-findings", "Detection findings"],
  ["risk-assessments", "Current risk assessments"],
  ["threat-indicators", "Threat indicators"],
  ["detection-rules", "Detection rules"],
  ["analyst-workload", "Analyst workload"],
];
export default function ReportPanel({ period }) {
  const { user } = useAuth(),
    [kind, setKind] = useState("security-summary"),
    [format, setFormat] = useState("csv"),
    [limit, setLimit] = useState(1000),
    [offset, setOffset] = useState(0);
  const [pending, setPending] = useState(false),
    [result, setResult] = useState(null),
    [error, setError] = useState("");
  const active = useRef(null);
  useEffect(() => () => active.current?.abort(), []);
  async function generate(e) {
    e.preventDefault();
    if (pending || active.current) return;
    const controller = new AbortController();
    active.current = controller;
    setPending(true);
    setError("");
    setResult(null);
    try {
      const response = await downloadReport(
        kind,
        {
          ...period.params,
          format,
          limit: Number(limit),
          offset: Number(offset),
        },
        controller.signal,
      );
      if (controller.signal.aborted) return;
      const url = URL.createObjectURL(response.data),
        a = document.createElement("a");
      a.href = url;
      a.download = `${kind}.${format}`;
      document.body.appendChild(a);
      a.click();
      a.remove();
      setTimeout(() => URL.revokeObjectURL(url), 1000);
      let metadata = {
        rows: response.headers["x-export-rows"],
        more: response.headers["x-export-has-more"] === "true",
        next: response.headers["x-export-next-offset"],
      };
      if (format === "json") {
        const body = JSON.parse(await response.data.text());
        metadata = {
          rows: body.returned_rows,
          more: body.has_more,
          next: body.next_offset,
        };
      }
      if (!controller.signal.aborted) setResult(metadata);
    } catch (failure) {
      if (!controller.signal.aborted) setError(failure.message);
    } finally {
      active.current = null;
      if (!controller.signal.aborted) setPending(false);
    }
  }
  return (
    <Panel
      title="Reports & exports"
      subtitle="A bounded export of selected data. Downloads require an authenticated analyst or administrator."
    >
      <div className="analytics-report-intro">
        <FileText size={30} />
        <div>
          <h3>From investigation to a shareable report</h3>
          <p>
            Export the current UTC period as structured JSON or spreadsheet-safe
            CSV. Reports include current case states and scores.
          </p>
        </div>
        <Badge>ON DEMAND</Badge>
      </div>
      <div className="analytics-scope">
        <span>{utc(period.params.start)}</span>
        <span>→</span>
        <span>{utc(period.params.end)}</span>
      </div>
      {user.role === "VIEWER" ? (
        <div className="info-note">
          Your VIEWER role can read analytics. Report downloads require ADMIN or
          ANALYST.
        </div>
      ) : (
        <form className="analytics-report-form" onSubmit={generate}>
          <label>
            <span id="report-type-label">Report type</span>
            <select
              aria-labelledby="report-type-label"
              value={kind}
              onChange={(e) => {
                setKind(e.target.value);
                setOffset(0);
                setResult(null);
              }}
              disabled={pending}
            >
              {types
                .filter(
                  ([key]) =>
                    key !== "analyst-workload" || user.role === "ADMIN",
                )
                .map(([key, name]) => (
                  <option key={key} value={key}>
                    {name}
                  </option>
                ))}
            </select>
          </label>
          <label>
            <span id="report-format-label">Format</span>
            <select
              aria-labelledby="report-format-label"
              value={format}
              onChange={(e) => setFormat(e.target.value)}
              disabled={pending}
            >
              <option value="csv">CSV</option>
              <option value="json">JSON</option>
            </select>
          </label>
          <label>
            Maximum rows
            <input
              type="number"
              min="1"
              max="5000"
              required
              value={limit}
              onChange={(e) => setLimit(e.target.value)}
              disabled={pending}
            />
          </label>
          <label>
            Row offset
            <input
              type="number"
              min="0"
              max="1000000"
              required
              value={offset}
              onChange={(e) => setOffset(e.target.value)}
              disabled={pending}
            />
          </label>
          <button className="button primary" disabled={pending}>
            <Download size={16} />
            {pending ? "Generating report…" : "Generate report"}
          </button>
        </form>
      )}
      {error && (
        <div className="soc-error" role="alert">
          {error}
        </div>
      )}
      {result && (
        <div className="analytics-export-success" role="status">
          Downloaded {result.rows ?? "selected"} rows.
          {result.more && (
            <>
              {" "}
              More rows are available.{" "}
              <button
                className="button secondary small"
                onClick={() => {
                  setOffset(Number(result.next));
                  setResult(null);
                }}
              >
                Prepare next page
              </button>
            </>
          )}
        </div>
      )}
      <p className="analytics-footnote">
        Security summary includes executive KPIs, response metrics, critical
        cases, trends, rules, risk distribution and intelligence. JSON retains
        structured sections; CSV uses section / metric / value rows. No report
        is stored in a public download directory.
      </p>
    </Panel>
  );
}
