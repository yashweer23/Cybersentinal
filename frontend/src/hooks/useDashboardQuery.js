import { useQuery } from "@tanstack/react-query";
import { useDashboard } from "../context/DashboardContext";
import { dashboardGet } from "../services/dashboardApi";
export function polling(preferences, interval) {
  return (query) =>
    preferences.autoRefresh &&
    ![401, 403, 404, 422].includes(query.state.error?.response?.status)
      ? interval
      : false;
}
export function useDashboardQuery(endpoint, options = {}) {
  const { range, preferences } = useDashboard();
  const { scoped = true, interval = 30000, params = {} } = options;
  const parameters = scoped ? { range, ...params } : params;
  return useQuery({
    queryKey: ["dashboard", endpoint, parameters],
    queryFn: ({ signal }) => dashboardGet(endpoint, parameters, signal),
    refetchInterval: polling(preferences, interval),
  });
}
