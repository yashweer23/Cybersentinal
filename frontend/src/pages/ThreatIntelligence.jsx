import {
  Reputation,
  IntelligenceDetail,
  staleResult,
} from "../components/threats/IntelligenceResult";
export { Reputation } from "../components/threats/IntelligenceResult";
import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useSearchParams } from "react-router-dom";
import {
  Database,
  Globe2,
  Search,
  ShieldAlert,
  ShieldQuestion,
} from "lucide-react";
import { useAuth } from "../context/AuthContext";
import { useDashboard } from "../context/DashboardContext";
import { useDashboardQuery, polling } from "../hooks/useDashboardQuery";
import {
  getProviders,
  listThreats,
  lookupThreat,
} from "../services/threatsApi";
import {
  Badge,
  DataTable,
  ErrorState,
  MetricCard,
  PageHeading,
  Pagination,
  Panel,
  QueryState,
  Time,
} from "../components/common/UI";
import { label, number } from "../utils/format";
export function ProviderCards({ data }) {
  return (
    <div className="provider-grid">
      {data.providers.map((p) => (
        <div className="provider-card" key={p.name}>
          <div>
            <Globe2 size={17} />
            <strong>
              {p.name === "AlienVaultOTX" ? "AlienVault OTX" : p.name}
            </strong>
          </div>
          <Badge tone={p.active ? "low" : "neutral"}>
            {p.name.toLowerCase().includes("mock") && data.simulation
              ? "Simulated"
              : p.active
                ? "Active"
                : !p.configured
                  ? "Not configured"
                  : p.enabled
                    ? "Configured"
                    : "Disabled"}
          </Badge>
          <small>
            {p.last_status
              ? `Last result: ${label(p.last_status)}`
              : p.active
                ? "Available for explicit lookups"
                : "No active lookup provider"}
          </small>
          {p.next_allowed_at && (
            <small>
              Next allowed <Time value={p.next_allowed_at} />
            </small>
          )}
        </div>
      ))}
    </div>
  );
}
export default function ThreatIntelligence() {
  const { user } = useAuth();
  const { preferences } = useDashboard();
  const client = useQueryClient();
  const [search] = useSearchParams();
  const [ip, setIp] = useState(search.get("ip") || ""),
    [indicator, setIndicator] = useState(search.get("ip") || ""),
    [offset, setOffset] = useState(0),
    [selected, setSelected] = useState(null);
  const summary = useDashboardQuery("threats/summary");
  const providers = useQuery({
    queryKey: ["threats", "providers"],
    queryFn: ({ signal }) => getProviders(signal),
    refetchInterval: polling(preferences, 30000),
  });
  const params = { limit: 10, offset, ...(indicator ? { indicator } : {}) };
  const cache = useQuery({
    queryKey: ["threats", "cache", params],
    queryFn: ({ signal }) => listThreats(params, signal),
    refetchInterval: polling(preferences, 30000),
  });
  const canLookup = ["ADMIN", "ANALYST"].includes(user.role);
  const lookup = useMutation({
    mutationFn: lookupThreat,
    onSuccess: (data) => {
      setSelected(data);
      void client.invalidateQueries({ queryKey: ["threats"] });
      void client.invalidateQueries({
        queryKey: ["dashboard", "threats/summary"],
      });
      void client.invalidateQueries({
        queryKey: ["dashboard", "threats/top-ips"],
      });
    },
  });
  return (
    <>
      <PageHeading
        title="Threat intelligence"
        description="Reputation context, provider coverage and cached indicators."
      >
        <Badge tone={providers.data?.simulation ? "simulation" : "neutral"}>
          {providers.isError
            ? "Provider status unavailable"
            : providers.data
              ? providers.data.simulation
                ? "Simulated mode"
                : providers.data.mode === "live"
                  ? "Live mode"
                  : "Unknown mode"
              : "Checking mode"}
        </Badge>
      </PageHeading>
      <QueryState query={summary}>
        {(d) => (
          <div className="metrics-grid four">
            <MetricCard
              label="Cached indicators"
              value={d.cached_indicators}
              icon={Database}
              subtitle="Checked within selected period"
            />
            <MetricCard
              label="Malicious"
              value={d.malicious_indicators}
              icon={ShieldAlert}
              tone="critical"
              subtitle={
                d.simulation
                  ? "Simulated reputation"
                  : "Current cached reputation"
              }
            />
            <MetricCard
              label="Suspicious"
              value={d.suspicious_indicators}
              icon={Globe2}
              tone="high"
              subtitle="Current cached reputation"
            />
            <MetricCard
              label="Unknown"
              value={d.unknown_indicators}
              icon={ShieldQuestion}
              subtitle="Unknown is not a clean verdict"
            />
          </div>
        )}
      </QueryState>
      <div className="soc-section">
        <Panel
          title="Intelligence providers"
          subtitle="Configuration status only; opening this page makes no external lookup"
        >
          <QueryState query={providers} strict>
            {(d) => (
              <>
                <ProviderCards data={d} />
                <div className="panel-footnote">{d.note}</div>
              </>
            )}
          </QueryState>
        </Panel>
      </div>
      <form
        className="lookup-form filter-panel"
        onSubmit={(e) => {
          e.preventDefault();
          setOffset(0);
          setIndicator(ip.trim());
          setSelected(null);
        }}
      >
        <label>
          IP address
          <input
            value={ip}
            onChange={(e) => setIp(e.target.value)}
            placeholder="e.g. 198.51.100.73"
            maxLength={45}
          />
        </label>
        <button className="button secondary" type="submit">
          <Search size={15} />
          Search cache
        </button>
        {canLookup && (
          <button
            className="button"
            type="button"
            disabled={!ip.trim() || lookup.isPending}
            onClick={() => lookup.mutate(ip.trim())}
          >
            {lookup.isPending ? "Looking up…" : "Run lookup"}
          </button>
        )}
        <p>
          {canLookup
            ? "Run lookup uses the server’s configured provider mode."
            : "Viewer access · cached intelligence only."}
        </p>
      </form>
      {lookup.isError && <ErrorState error={lookup.error} />}
      {selected && (
        <div className="soc-section">
          <IntelligenceDetail
            result={selected}
            close={() => setSelected(null)}
          />
        </div>
      )}
      <Panel
        title="Cached intelligence"
        subtitle="All retained cache records; independent of the summary time range"
      >
        <QueryState query={cache}>
          {(d) => (
            <>
              <DataTable
                caption="Cached threat intelligence"
                rows={d.items.map((r) => ({
                  ...r,
                  cache_key: `${r.mode}:${r.indicator}`,
                }))}
                rowKey="cache_key"
                emptyTitle="No threat intelligence cached yet"
                columns={[
                  {
                    key: "indicator",
                    title: "Indicator",
                    render: (r) => (
                      <button
                        className="text-button mono"
                        onClick={() => setSelected(r)}
                      >
                        {r.indicator}
                      </button>
                    ),
                  },
                  {
                    key: "reputation_level",
                    title: "Reputation",
                    render: (r) => <Reputation result={r} />,
                  },
                  {
                    key: "normalized_score",
                    title: "Score",
                    render: (r) =>
                      staleResult(r) ? "Unknown" : number(r.normalized_score),
                  },
                  {
                    key: "simulation",
                    title: "Source mode",
                    render: (r) => (
                      <Badge tone={r.simulation ? "simulation" : "neutral"}>
                        {r.simulation ? "Simulated" : "Live"}
                      </Badge>
                    ),
                  },
                  {
                    key: "checked_at",
                    title: "Checked · UTC",
                    render: (r) => <Time value={r.checked_at} />,
                  },
                  {
                    key: "expires_at",
                    title: "Expires · UTC",
                    render: (r) => <Time value={r.expires_at} />,
                  },
                ]}
              />
              <Pagination
                offset={offset}
                limit={10}
                total={d.total}
                onChange={setOffset}
              />
            </>
          )}
        </QueryState>
      </Panel>
      {summary.data && (
        <div className="scope-note">
          <span>
            Last refresh <Time value={summary.data.last_refresh} />
          </span>
          <span>
            {number(summary.data.expired_indicators)} expired ·{" "}
            {number(summary.data.incompatible_indicators)} incompatible in
            selected period
          </span>
        </div>
      )}
    </>
  );
}
