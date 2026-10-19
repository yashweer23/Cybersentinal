import { useState } from "react";
import { useAuth } from "../../context/AuthContext";
import {
  useIncidentMutation,
  useIncidentSection,
} from "../../hooks/useIncident";
import { refreshIncidentIntelligence } from "../../services/incidentsApi";
import {
  Badge,
  EmptyState,
  ErrorState,
  Pagination,
  Panel,
  QueryState,
} from "../common/UI";
import { Reputation, staleResult } from "../threats/IntelligenceResult";
import { label, number, utc } from "../../utils/format";
import { EvidenceFields } from "./EvidenceFields";

export default function ThreatIntelligencePanel({
  incidentId,
  compact = false,
}) {
  const { user } = useAuth();
  const [offset, setOffset] = useState(0);
  const query = useIncidentSection(incidentId, "threat-intelligence", {
    limit: 10,
    offset,
  });
  const mutation = useIncidentMutation(incidentId, "intelligence", () =>
    refreshIncidentIntelligence(incidentId),
  );
  const canRefresh = !compact && ["ADMIN", "ANALYST"].includes(user.role);
  return (
    <Panel
      title="Threat intelligence"
      subtitle="Cached observations · opening this case makes no external lookup"
      action={
        canRefresh && (
          <button
            className="button secondary small"
            disabled={mutation.isPending}
            onClick={() => mutation.mutate()}
          >
            {mutation.isPending
              ? "Refreshing intelligence…"
              : "Refresh intelligence"}
          </button>
        )
      }
    >
      {mutation.isError && <ErrorState error={mutation.error} />}
      {mutation.isSuccess && (
        <p
          className={
            mutation.data.complete && !mutation.data.failed_lookups
              ? "case-success case-content"
              : "info-note"
          }
          role="status"
        >
          {mutation.data.complete && !mutation.data.failed_lookups
            ? "Intelligence refresh completed."
            : "Intelligence refresh partially completed; inspect provider results."}{" "}
          {mutation.data.indicators_evaluated} indicators evaluated ·{" "}
          {mutation.data.failed_lookups} failed ·{" "}
          {mutation.data.unknown_lookups} unknown.
          {mutation.data.error ? ` ${mutation.data.error}` : ""}
        </p>
      )}
      <QueryState query={query} strict>
        {(data) => (
          <div className="case-content">
            {!data.total_indicators && (
              <EmptyState
                title="No related indicators"
                description="No source or destination IPs are linked to this case."
              />
            )}
            {data.indicators.map((result) => (
              <article
                className="case-indicator"
                key={`${result.mode}:${result.indicator}`}
              >
                <div className="case-indicator-heading">
                  <strong className="mono">{result.indicator}</strong>
                  <Reputation result={result} />
                  <Badge tone={result.simulation ? "simulation" : "neutral"}>
                    {result.simulation
                      ? "Simulated intelligence"
                      : "Real intelligence"}
                  </Badge>
                </div>
                <p>
                  Normalized score:{" "}
                  <strong>
                    {staleResult(result)
                      ? "Unknown"
                      : number(result.normalized_score)}
                  </strong>{" "}
                  · {label(result.lookup_status)}
                </p>
                <p className="case-small">{result.explanation}</p>
                <small className="muted">
                  Checked {utc(result.checked_at)} · Expires{" "}
                  {utc(result.expires_at)}
                </small>
                {!compact && (
                  <details className="case-raw">
                    <summary>
                      Provider results ({result.providers.length})
                    </summary>
                    {result.providers.map((provider) => (
                      <section
                        className="case-provider-result"
                        key={provider.provider}
                      >
                        <div className="inline-badges">
                          <strong>{provider.provider}</strong>
                          <Badge>{label(provider.lookup_status)}</Badge>
                          <Badge
                            tone={
                              provider.simulation ? "simulation" : "neutral"
                            }
                          >
                            {provider.simulation
                              ? "Simulated"
                              : "Real provider"}
                          </Badge>
                        </div>
                        <p>{provider.explanation}</p>
                        <EvidenceFields
                          data={Object.fromEntries(
                            Object.entries({
                              stored_normalized_score:
                                provider.normalized_score,
                              provider_score: provider.provider_score,
                              reports: provider.reports,
                              country: provider.country,
                              isp: provider.isp,
                              tags: provider.tags?.length
                                ? provider.tags
                                : null,
                              checked_at: provider.checked_at
                                ? utc(provider.checked_at)
                                : null,
                              expires_at: provider.expires_at
                                ? utc(provider.expires_at)
                                : null,
                              retry_at: provider.retry_at
                                ? utc(provider.retry_at)
                                : null,
                            }).filter(([, v]) => v != null),
                          )}
                        />
                        <p className="case-small muted">
                          Provider observations are historical when expired.
                          Missing metrics are not inferred.
                        </p>
                      </section>
                    ))}
                  </details>
                )}
              </article>
            ))}
            {data.missing_indicators.map((ip) => (
              <div className="case-indicator" key={ip}>
                <strong className="mono">{ip}</strong>
                <p className="muted">
                  No cached intelligence in {data.mode} mode. Reputation is
                  unknown.
                </p>
              </div>
            ))}
            <Pagination
              offset={offset}
              limit={10}
              total={data.total_indicators}
              onChange={setOffset}
            />
            {!compact && (
              <p className="case-small muted">
                Refresh uses the server’s configured mode and rate limits.
                Results may be simulated, unavailable, or unknown; unknown does
                not mean safe. Intelligence refresh does not recalculate case
                risk.
              </p>
            )}
          </div>
        )}
      </QueryState>
    </Panel>
  );
}
