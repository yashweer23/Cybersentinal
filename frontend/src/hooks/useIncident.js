import {
  useIsMutating,
  useMutation,
  useQuery,
  useQueryClient,
} from "@tanstack/react-query";
import { useDashboard } from "../context/DashboardContext";
import { polling } from "./useDashboardQuery";
import { getIncident, incidentSection } from "../services/incidentsApi";

export function useIncident(id) {
  const { preferences } = useDashboard();
  return useQuery({
    queryKey: ["incident", id],
    queryFn: ({ signal }) => getIncident(id, signal),
    refetchInterval: polling(preferences, 15000),
  });
}
export function useIncidentSection(id, section, params = {}, options = {}) {
  const { preferences } = useDashboard();
  const interval =
    section === "threat-intelligence"
      ? false
      : section === "timeline"
        ? 30000
        : 15000;
  return useQuery({
    queryKey: ["incident", id, section, params],
    queryFn: ({ signal }) => incidentSection(id, section, params, signal),
    refetchInterval: interval ? polling(preferences, interval) : false,
    refetchOnWindowFocus: section !== "threat-intelligence",
    ...options,
  });
}
export function useIncidentMutation(id, kind, mutationFn, onSuccess) {
  const client = useQueryClient();
  const mutationKey = ["incident-mutation", id, kind];
  const pending = useIsMutating({ mutationKey });
  const mutation = useMutation({
    mutationKey,
    mutationFn,
    retry: false,
    onSuccess: async (data) => {
      const keys = [
        ["ai", id],
        ["incident", id],
        ["incident", id, "timeline"],
      ];
      if (kind === "comment") keys.push(["incident", id, "comments"]);
      else if (kind === "intelligence")
        keys.push(
          ["incident", id, "threat-intelligence"],
          ["threats"],
          ["dashboard", "threats/summary"],
          ["dashboard", "threats/top-ips"],
        );
      else
        keys.push(
          ["incidents"],
          ["dashboard", "overview"],
          ["dashboard", "incidents/recent"],
          ["dashboard", "incidents/status"],
        );
      await Promise.all(
        keys.map((queryKey) =>
          client.invalidateQueries({
            queryKey,
            exact: queryKey.length === 2 && queryKey[0] === "incident",
          }),
        ),
      );
      onSuccess?.(data);
    },
    onError: () => {
      // A timeout can follow a committed write. Re-read authoritative state without retrying a mutation.
      void client.invalidateQueries({ queryKey: ["incident", id] });
    },
  });
  // Keep controls disabled if their tab remounts while this case's write is pending.
  return { ...mutation, isPending: mutation.isPending || pending > 0 };
}
