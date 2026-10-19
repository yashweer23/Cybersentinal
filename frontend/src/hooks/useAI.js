import {
  useQuery,
  useMutation,
  useQueryClient,
  useIsMutating,
} from "@tanstack/react-query";
import { useDashboard } from "../context/DashboardContext";
import { polling } from "./useDashboardQuery";
import { getAIStatus, readAnalysis, analyzeIncident } from "../services/aiApi";
export function useAIStatus() {
  return useQuery({
    queryKey: ["ai-status"],
    queryFn: ({ signal }) => getAIStatus(signal),
    staleTime: 30000,
  });
}
export function useAnalysis(id) {
  const { preferences } = useDashboard();
  return useQuery({
    queryKey: ["ai", id, "current"],
    queryFn: ({ signal }) => readAnalysis(id, signal),
    refetchInterval: polling(preferences, 15000),
  });
}
export function useGenerateAnalysis(id) {
  const client = useQueryClient();
  const mutationKey = ["ai-generate", id];
  const count = useIsMutating({ mutationKey });
  const mutation = useMutation({
    mutationKey,
    mutationFn: (force) => analyzeIncident(id, force),
    retry: false,
    onSuccess: async (data) => {
      client.setQueryData(["ai", id, "current"], { analysis: data });
      await Promise.all(
        [
          ["ai", id, "history"],
          ["ai-status"],
          ["dashboard", "system/health"],
        ].map((queryKey) => client.invalidateQueries({ queryKey })),
      );
    },
    onError: () => {
      void client.invalidateQueries({ queryKey: ["ai", id, "current"] });
    },
  });
  return { ...mutation, isPending: mutation.isPending || count > 0 };
}
