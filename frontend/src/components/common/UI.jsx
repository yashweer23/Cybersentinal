import { ArrowUpRight, Inbox, RefreshCw, TriangleAlert } from "lucide-react";
import { Link } from "react-router-dom";
import { ContractError } from "../../services/contracts";
import { errorMessage } from "../../services/api";
import { label, number, riskLevel, shortTime, utc } from "../../utils/format";
export function Badge({ children, tone = "neutral" }) {
  return (
    <span className={`soc-badge tone-${tone.toLowerCase()}`}>{children}</span>
  );
}
export const SeverityBadge = ({ value }) => (
  <Badge tone={value}>{label(value)}</Badge>
);
export const StatusBadge = ({ value }) => (
  <Badge tone={value}>{label(value)}</Badge>
);
export function RiskBadge({ value }) {
  return value == null ? (
    <span className="muted">—</span>
  ) : (
    <span
      className={`risk-score text-${riskLevel(value).toLowerCase()}`}
      title={`${riskLevel(value)} risk category`}
    >
      <b>{number(value, 1)}</b>
      <small>/100</small>
    </span>
  );
}
export const Time = ({ value }) => (
  <time dateTime={value || undefined} title={utc(value)}>
    {shortTime(value)}
  </time>
);
export function PageHeading({
  eyebrow = "SECURITY OPERATIONS",
  title,
  description,
  children,
}) {
  return (
    <div className="soc-page-heading">
      <div>
        <div className="eyebrow">{eyebrow}</div>
        <h1>{title}</h1>
        {description && <p>{description}</p>}
      </div>
      {children && <div className="heading-actions">{children}</div>}
    </div>
  );
}
export function Panel({ title, subtitle, action, children, className = "" }) {
  return (
    <section className={`soc-panel ${className}`}>
      <div className="soc-panel-heading">
        <div>
          <h2>{title}</h2>
          {subtitle && <p>{subtitle}</p>}
        </div>
        {action}
      </div>
      {children}
    </section>
  );
}
export const PanelLink = ({ to, children }) => (
  <Link className="panel-link" to={to}>
    {children}
    <ArrowUpRight size={14} />
  </Link>
);
export function LoadingSkeleton({ rows = 3 }) {
  return (
    <div className="skeleton-wrap" role="status" aria-label="Loading data">
      {Array.from({ length: rows }, (_, i) => (
        <div className="skeleton" key={i} />
      ))}
    </div>
  );
}
export function EmptyState({
  title = "No activity in this period",
  description = "Try another time range or ingest security events to get started.",
}) {
  return (
    <div className="empty-state">
      <Inbox size={26} />
      <strong>{title}</strong>
      <p>{description}</p>
    </div>
  );
}
export function ErrorState({ error, retry, stale = false }) {
  const message =
    error instanceof ContractError
      ? error.message
      : error?.response?.status === 403
        ? "Your role does not have permission to perform this action."
        : errorMessage(error);
  return (
    <div className="soc-error" role="alert">
      <TriangleAlert size={18} />
      <div>
        <strong>
          {stale
            ? "Refresh failed · showing previous data"
            : "Data unavailable"}
        </strong>
        <p>{message}</p>
      </div>
      {retry && (
        <button
          className="icon-button"
          aria-label="Retry request"
          onClick={() => void retry()}
        >
          <RefreshCw size={16} />
        </button>
      )}
    </div>
  );
}
export function QueryState({ query, children, strict = false }) {
  if (query.isPending) return <LoadingSkeleton />;
  if (query.isError && (!query.data || strict))
    return <ErrorState error={query.error} retry={query.refetch} />;
  return (
    <>
      {query.isError && (
        <ErrorState error={query.error} retry={query.refetch} stale />
      )}
      {query.data !== undefined && children(query.data)}
    </>
  );
}
export function DataTable({
  columns,
  rows,
  rowKey,
  caption,
  emptyTitle,
  emptyDescription,
}) {
  if (!rows.length)
    return (
      <EmptyState
        title={emptyTitle || "No matching records"}
        description={
          emptyDescription ||
          "Adjust the filters or time range to see more activity."
        }
      />
    );
  return (
    <div
      className="table-scroll"
      tabIndex={0}
      role="region"
      aria-label={`${caption} table`}
    >
      <table className="soc-table">
        <caption className="sr-only">{caption}</caption>
        <thead>
          <tr>
            {columns.map((c) => (
              <th
                key={c.key}
                scope="col"
                className={c.numeric ? "numeric" : ""}
              >
                {c.title}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {rows.map((row) => (
            <tr key={row[rowKey]}>
              {columns.map((c) => (
                <td key={c.key} className={c.numeric ? "numeric" : ""}>
                  {c.render ? c.render(row) : (row[c.key] ?? "—")}
                </td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
export function Pagination({ offset, limit, total, onChange }) {
  return (
    <div className="pagination">
      <span>
        {total
          ? `${number(offset + 1)}–${number(Math.min(offset + limit, total))} of ${number(total)}`
          : "0 results"}{" "}
        <span className="muted">· Page {Math.floor(offset / limit) + 1}</span>
      </span>
      <div>
        <button
          className="button secondary small"
          disabled={offset === 0}
          onClick={() => onChange(Math.max(0, offset - limit))}
        >
          Previous
        </button>
        <button
          className="button secondary small"
          disabled={offset + limit >= total}
          onClick={() => onChange(offset + limit)}
        >
          Next
        </button>
      </div>
    </div>
  );
}
export function MetricCard({
  label: title,
  value,
  icon: Icon,
  subtitle,
  tone = "mint",
}) {
  return (
    <article className={`metric-card metric-${tone}`}>
      <div className="metric-label">
        {title}
        <Icon size={17} />
      </div>
      <div className="metric-value">{number(value, 1)}</div>
      <p>{subtitle}</p>
    </article>
  );
}
