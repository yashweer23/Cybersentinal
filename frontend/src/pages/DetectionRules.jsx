import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useAuth } from "../context/AuthContext";
import { useDashboardQuery } from "../hooks/useDashboardQuery";
import { getRules, setRuleEnabled } from "../services/rulesApi";
import {
  Badge,
  DataTable,
  ErrorState,
  PageHeading,
  Panel,
  QueryState,
  SeverityBadge,
  Time,
} from "../components/common/UI";
import { number } from "../utils/format";
export default function DetectionRules() {
  const { user } = useAuth();
  const client = useQueryClient();
  const query = useQuery({
    queryKey: ["rules"],
    queryFn: ({ signal }) => getRules(signal),
  });
  const stats = useDashboardQuery("detection/rules");
  const mutation = useMutation({
    mutationFn: ({ id, enabled }) => setRuleEnabled(id, enabled),
    onSuccess: () => {
      void client.invalidateQueries({ queryKey: ["rules"] });
      void client.invalidateQueries({
        queryKey: ["dashboard", "detection/rules"],
      });
    },
  });
  const counts = new Map((stats.data?.items || []).map((r) => [r.rule_id, r]));
  return (
    <>
      <PageHeading
        title="Detection rules"
        description="Explainable behavioral checks. Thresholds and rule state are stored in PostgreSQL."
      >
        <Badge>
          {user.role === "ADMIN"
            ? "Administrator controls"
            : "Read-only configuration"}
        </Badge>
      </PageHeading>
      {mutation.isError && <ErrorState error={mutation.error} />}{" "}
      {mutation.isSuccess && (
        <p className="success-note" role="status">
          Rule state updated. Changes apply to future detection runs.
        </p>
      )}
      {stats.isError && (
        <ErrorState error={stats.error} retry={stats.refetch} />
      )}
      <Panel
        title="Rule library"
        subtitle="Finding counts reflect the selected period; enabling a rule does not execute it"
      >
        <QueryState query={query}>
          {(data) => (
            <DataTable
              caption="Detection rules"
              rows={data}
              rowKey="rule_id"
              emptyTitle="No rules have been seeded"
              columns={[
                {
                  key: "rule_id",
                  title: "Rule",
                  render: (r) => (
                    <span className="mono green-text">{r.rule_id}</span>
                  ),
                },
                {
                  key: "name",
                  title: "Name & configuration",
                  render: (r) => (
                    <div className="rule-description">
                      <strong>{r.name}</strong>
                      <p>{r.description}</p>
                      <details>
                        <summary>View configuration</summary>
                        <pre>{JSON.stringify(r.configuration, null, 2)}</pre>
                      </details>
                    </div>
                  ),
                },
                {
                  key: "severity",
                  title: "Default severity",
                  render: (r) => <SeverityBadge value={r.severity} />,
                },
                {
                  key: "enabled",
                  title: "State",
                  render: (r) =>
                    user.role === "ADMIN" ? (
                      <button
                        className={`rule-toggle ${r.enabled ? "enabled" : ""}`}
                        role="switch"
                        aria-checked={r.enabled}
                        aria-label={`${r.enabled ? "Disable" : "Enable"} ${r.rule_id}`}
                        disabled={mutation.isPending}
                        onClick={() =>
                          mutation.mutate({
                            id: r.rule_id,
                            enabled: !r.enabled,
                          })
                        }
                      >
                        <i />
                        {r.enabled ? "Enabled" : "Disabled"}
                      </button>
                    ) : (
                      <Badge tone={r.enabled ? "low" : "neutral"}>
                        {r.enabled ? "Enabled" : "Disabled"}
                      </Badge>
                    ),
                },
                {
                  key: "finding_count",
                  title: "Findings",
                  numeric: true,
                  render: (r) =>
                    stats.isError
                      ? "Unavailable"
                      : number(counts.get(r.rule_id)?.finding_count),
                },
                {
                  key: "latest_finding_timestamp",
                  title: "Latest detection · UTC",
                  render: (r) =>
                    stats.isError ? (
                      "Unavailable"
                    ) : (
                      <Time
                        value={counts.get(r.rule_id)?.latest_finding_timestamp}
                      />
                    ),
                },
              ]}
            />
          )}
        </QueryState>
      </Panel>
    </>
  );
}
