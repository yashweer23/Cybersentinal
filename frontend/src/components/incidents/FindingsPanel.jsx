import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { useIncidentSection } from "../../hooks/useIncident";
import { getFinding, getRisk } from "../../services/incidentsApi";
import {
  EmptyState,
  Pagination,
  Panel,
  QueryState,
  RiskBadge,
  SeverityBadge,
} from "../common/UI";
import { number, utc } from "../../utils/format";
import { EvidenceFields, RawData } from "./EvidenceFields";
import RiskBreakdown from "./RiskBreakdown";
function FindingDetails({ finding }) {
  const evidence = useQuery({
    queryKey: ["finding", finding.finding_id],
    queryFn: ({ signal }) => getFinding(finding.finding_id, signal),
  });
  const risk = useQuery({
    queryKey: ["risk", finding.assessment_id],
    queryFn: ({ signal }) => getRisk(finding.assessment_id, signal),
    enabled: Boolean(finding.assessment_id),
  });
  return (
    <div className="case-finding-detail">
      <QueryState query={evidence}>
        {(data) => (
          <>
            <p>{data.description}</p>
            <h4>Detection evidence</h4>
            <EvidenceFields
              data={data.evidence_data}
              omit={["event_ids", "evidence_event_ids"]}
            />
            <details className="case-raw">
              <summary>
                Related event IDs ({data.evidence_event_ids.length})
              </summary>
              <ul className="case-id-list">
                {data.evidence_event_ids.map((id) => (
                  <li key={id} className="mono">
                    {id}
                  </li>
                ))}
              </ul>
            </details>
            <RawData title="View raw evidence" value={data.evidence_data} />
          </>
        )}
      </QueryState>
      <div className="case-correlation">
        <h4>Correlation decision</h4>
        <p>{finding.relationship_reason}</p>
        <EvidenceFields data={finding.correlation_data} />
      </div>
      {finding.assessment_id && (
        <details className="case-raw">
          <summary>Finding risk assessment</summary>
          <QueryState query={risk}>
            {(data) => <RiskBreakdown assessment={data} />}
          </QueryState>
        </details>
      )}
    </div>
  );
}
export default function FindingsPanel({ incidentId }) {
  const [offset, setOffset] = useState(0),
    [expanded, setExpanded] = useState(null);
  const query = useIncidentSection(incidentId, "findings", {
    limit: 10,
    offset,
  });
  return (
    <Panel
      title="Linked detection findings"
      subtitle="Detection evidence remains separate from case risk"
    >
      <QueryState query={query}>
        {(data) => (
          <>
            {!data.items.length && (
              <EmptyState
                title="No linked findings"
                description="This case has no retained detection links."
              />
            )}
            <div className="case-findings">
              {data.items.map((f) => (
                <article className="case-finding" key={f.finding_id}>
                  <div className="case-finding-heading">
                    <div>
                      <span className="mono case-small muted">
                        {f.finding_id}
                      </span>
                      <h3>
                        {f.rule_id} · {f.rule_name}
                      </h3>
                      <p>{f.title}</p>
                    </div>
                    <SeverityBadge value={f.severity} />
                  </div>
                  <dl className="case-facts">
                    <div>
                      <dt>Confidence</dt>
                      <dd>{f.confidence}%</dd>
                    </div>
                    <div>
                      <dt>Finding risk</dt>
                      <dd>
                        <RiskBadge value={f.risk_score} />
                      </dd>
                    </div>
                    <div>
                      <dt>Source IP</dt>
                      <dd className="mono">{f.source_ip || "Not recorded"}</dd>
                    </div>
                    <div>
                      <dt>Account</dt>
                      <dd>{f.username || "Not recorded"}</dd>
                    </div>
                    <div>
                      <dt>Events observed</dt>
                      <dd>{number(f.event_count)}</dd>
                    </div>
                    <div>
                      <dt>First seen</dt>
                      <dd>{utc(f.first_seen)}</dd>
                    </div>
                    <div>
                      <dt>Last seen</dt>
                      <dd>{utc(f.last_seen)}</dd>
                    </div>
                  </dl>
                  <button
                    className="button secondary small"
                    aria-expanded={expanded === f.finding_id}
                    aria-controls={`finding-${f.finding_id}`}
                    onClick={() =>
                      setExpanded(
                        expanded === f.finding_id ? null : f.finding_id,
                      )
                    }
                  >
                    {expanded === f.finding_id
                      ? "Hide evidence"
                      : "Inspect evidence"}
                  </button>
                  {expanded === f.finding_id && (
                    <div id={`finding-${f.finding_id}`}>
                      <FindingDetails finding={f} />
                    </div>
                  )}
                </article>
              ))}
            </div>
            <Pagination
              offset={offset}
              limit={10}
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
