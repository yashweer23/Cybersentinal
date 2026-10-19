import { useEffect, useMemo, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { useDashboard } from "../context/DashboardContext";
import { analyticsGet } from "../services/analyticsApi";
export const ANALYTICS_PERIODS = ["24h", "7d", "30d", "90d"];
export function useAnalyticsPeriod() {
  const [search, setSearch] = useSearchParams();
  const { refreshTick, range, setRange } = useDashboard();
  const preset =
      search.get("period") ||
      (ANALYTICS_PERIODS.includes(range) ? range : "30d"),
    start = search.get("start"),
    end = search.get("end");
  const [clock, setClock] = useState(() => new Date());
  useEffect(() => setClock(new Date()), [preset, start, end, refreshTick]);
  const period = useMemo(() => {
    if (preset === "custom") {
      const a = new Date(start),
        b = new Date(end);
      if (
        !start ||
        !end ||
        !/(Z|[+-]\d\d:\d\d)$/.test(start) ||
        !/(Z|[+-]\d\d:\d\d)$/.test(end) ||
        !Number.isFinite(+a) ||
        !Number.isFinite(+b) ||
        b <= a ||
        b - a > 90 * 86400000
      )
        return { error: "Choose an ordered UTC range of at most 90 days." };
      return {
        params: { start: a.toISOString(), end: b.toISOString() },
        label: "Custom UTC range",
      };
    }
    if (!ANALYTICS_PERIODS.includes(preset))
      return { error: "Select a supported analytics period." };
    const days = preset === "24h" ? 1 : parseInt(preset, 10);
    return {
      params: {
        start: new Date(+clock - days * 86400000).toISOString(),
        end: clock.toISOString(),
      },
      label: `Last ${preset.toUpperCase()}`,
    };
  }, [preset, start, end, clock]);
  function update(values) {
    if (ANALYTICS_PERIODS.includes(values.period)) setRange(values.period);
    const next = new URLSearchParams(search);
    Object.entries(values).forEach(([k, v]) =>
      v == null ? next.delete(k) : next.set(k, v),
    );
    setSearch(next);
  }
  return {
    ...period,
    preset,
    update,
    section: search.get("section") || "executive",
  };
}
export function useAnalyticsQuery(
  endpoint,
  period,
  filters = {},
  enabled = true,
) {
  const params = { ...period.params, ...filters };
  return useQuery({
    queryKey: ["analytics", endpoint, params],
    queryFn: ({ signal }) => analyticsGet(endpoint, params, signal),
    enabled: enabled && !period.error,
    staleTime: 30000,
    refetchOnWindowFocus: false,
  });
}
