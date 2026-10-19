import { createContext, useContext, useEffect, useState } from "react";
import {
  QueryClient,
  QueryClientProvider,
  useQueryClient,
} from "@tanstack/react-query";
import { useAuth } from "./AuthContext";
export const ranges = ["1h", "6h", "24h", "7d", "30d", "90d"];
const Context = createContext(null);
const defaults = { defaultRange: "24h", autoRefresh: true, collapsed: false };
export function readPreferences(key) {
  try {
    const saved = JSON.parse(localStorage.getItem(key));
    return {
      defaultRange: ranges.includes(saved?.defaultRange)
        ? saved.defaultRange
        : "24h",
      autoRefresh:
        typeof saved?.autoRefresh === "boolean" ? saved.autoRefresh : true,
      collapsed:
        typeof saved?.collapsed === "boolean" ? saved.collapsed : false,
    };
  } catch {
    return defaults;
  }
}
export function shouldRetry(count, error) {
  return (
    count < 1 &&
    error?.name !== "ContractError" &&
    ![400, 401, 403, 404, 422].includes(error?.response?.status)
  );
}
function State({ children, storageKey }) {
  const queryClient = useQueryClient();
  const [preferences, setPreferences] = useState(() =>
    readPreferences(storageKey),
  );
  const [range, setRange] = useState(preferences.defaultRange);
  const [refreshTick, setRefreshTick] = useState(0);
  useEffect(() => {
    try {
      localStorage.setItem(storageKey, JSON.stringify(preferences));
    } catch {
      /* Storage is optional; in-memory preferences still work. */
    }
  }, [preferences, storageKey]);
  const refresh = () => {
    void queryClient.invalidateQueries();
    setRefreshTick((t) => t + 1);
  };
  return (
    <Context.Provider
      value={{
        range,
        setRange,
        preferences,
        setPreferences,
        refresh,
        refreshTick,
      }}
    >
      {children}
    </Context.Provider>
  );
}
function ScopedProvider({ children, storageKey }) {
  const [client] = useState(
    () =>
      new QueryClient({
        defaultOptions: {
          queries: {
            staleTime: 8000,
            gcTime: 120000,
            retry: shouldRetry,
            refetchOnWindowFocus: true,
            refetchIntervalInBackground: false,
          },
          mutations: { retry: false },
        },
      }),
  );
  useEffect(
    () => () => {
      void client.cancelQueries();
      client.clear();
    },
    [client],
  );
  return (
    <QueryClientProvider client={client}>
      <State storageKey={storageKey}>{children}</State>
    </QueryClientProvider>
  );
}
export function DashboardProvider({ children }) {
  const { user } = useAuth();
  // A user/role change replaces the whole cache and aborts in-flight queries.
  return (
    <ScopedProvider
      key={`${user.id}:${user.role}`}
      storageKey={`cybersentinel.preferences.${user.id}`}
    >
      {children}
    </ScopedProvider>
  );
}
export const useDashboard = () => useContext(Context);
