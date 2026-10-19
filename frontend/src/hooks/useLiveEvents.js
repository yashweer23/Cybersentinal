import { useCallback, useEffect, useRef, useState } from "react";
import { dashboardGet } from "../services/dashboardApi";
import { useDashboard } from "../context/DashboardContext";
export const MAX_LIVE_EVENTS = 500;
export function mergeEvents(existing, incoming, limit = MAX_LIVE_EVENTS) {
  const unique = new Map(existing.map((row) => [row.id, row]));
  incoming.forEach((row) => unique.set(row.id, row));
  return [...unique.values()]
    .sort((a, b) =>
      BigInt(a.ingestion_sequence) > BigInt(b.ingestion_sequence)
        ? -1
        : BigInt(a.ingestion_sequence) < BigInt(b.ingestion_sequence)
          ? 1
          : a.id.localeCompare(b.id),
    )
    .slice(0, limit);
}
export function useLiveEvents() {
  const { preferences, refreshTick, setPreferences } = useDashboard();
  const [rows, setRows] = useState([]);
  const [paused, setPaused] = useState(false);
  const [error, setError] = useState(null);
  const [loading, setLoading] = useState(true);
  const [updatedAt, setUpdatedAt] = useState(null);
  const [retryTick, setRetryTick] = useState(0);
  const cursor = useRef(null);
  const lastManual = useRef({ refreshTick: 0, retryTick: 0 });
  const retry = useCallback(() => setRetryTick((t) => t + 1), []);
  useEffect(() => {
    let disposed = false,
      timer,
      controller;
    const stop = () => {
      clearTimeout(timer);
      controller?.abort();
    };
    const run = async () => {
      if (disposed || document.hidden) return;
      controller = new AbortController();
      const signal = controller.signal;
      let delay = 5000;
      try {
        if (cursor.current === null) {
          const initial = await dashboardGet(
            "events/recent",
            { range: "24h", limit: 50 },
            signal,
          );
          if (disposed || signal.aborted) return;
          setRows((current) => mergeEvents(current, initial.items));
          cursor.current = initial.polling_cursor;
        } else {
          const page = await dashboardGet(
            "events/updates",
            { after_id: cursor.current, limit: 100 },
            signal,
          );
          if (disposed || signal.aborted) return;
          setRows((current) => mergeEvents(current, page.items));
          cursor.current = page.next_cursor; // Commit only after the validated page has been accepted.
          if (page.has_more) delay = 100;
        }
        setError(null);
        setUpdatedAt(new Date().toISOString());
      } catch (failure) {
        if (!disposed && !signal.aborted) setError(failure);
        if ([400, 401, 403, 404, 422].includes(failure.response?.status))
          delay = null;
      } finally {
        if (!disposed && !signal.aborted) {
          setLoading(false);
          if (delay !== null && !paused && preferences.autoRefresh)
            timer = setTimeout(run, delay);
        }
      }
    };
    const visibility = () => {
      stop();
      if (!document.hidden && !paused && preferences.autoRefresh) void run();
    };
    // Initial snapshot/manual refresh are available even when automatic polling is paused.
    const manual =
      lastManual.current.refreshTick !== refreshTick ||
      lastManual.current.retryTick !== retryTick;
    lastManual.current = { refreshTick, retryTick };
    if (
      cursor.current === null ||
      (!paused && preferences.autoRefresh) ||
      manual
    )
      void run();
    document.addEventListener("visibilitychange", visibility);
    return () => {
      disposed = true;
      stop();
      document.removeEventListener("visibilitychange", visibility);
    };
  }, [paused, preferences.autoRefresh, refreshTick, retryTick]);
  return {
    rows,
    paused,
    setPaused,
    error,
    loading,
    updatedAt,
    retry,
    clear: () => setRows([]),
    toggle: () => {
      if (!paused && preferences.autoRefresh) setPaused(true);
      else {
        setPaused(false);
        setPreferences((p) => ({ ...p, autoRefresh: true }));
      }
    },
    live: !paused && preferences.autoRefresh,
  };
}
