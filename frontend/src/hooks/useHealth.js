import { useCallback, useEffect, useRef, useState } from "react";
import axios from "axios";
import { fetchHealth } from "../services/api";

export function useHealth() {
  const [data, setData] = useState(null);
  const [error, setError] = useState(null);
  const [refreshing, setRefreshing] = useState(true);
  const [lastChecked, setLastChecked] = useState(null);
  const active = useRef(null);

  const refresh = useCallback(async () => {
    active.current?.abort();
    const controller = new AbortController();
    active.current = controller;
    setRefreshing(true);
    try {
      const result = await fetchHealth(controller.signal);
      if (!controller.signal.aborted) {
        setData(result);
        setError(null);
      }
    } catch (problem) {
      if (!axios.isCancel(problem) && !controller.signal.aborted) {
        setData(null); // Never leave an old healthy badge visible after connectivity is lost.
        setError(
          "Cannot reach the API. Check that the backend is running, then retry.",
        );
      }
    } finally {
      if (!controller.signal.aborted) {
        setRefreshing(false);
        setLastChecked(new Date());
      }
    }
  }, []);

  useEffect(() => {
    refresh();
    const interval = setInterval(() => {
      // The next poll runs after the previous request settles.
      if (!active.current || active.current.signal.aborted) return;
      // Axios aborts previous requests in refresh; use a polling period above the timeout.
      refresh();
    }, 20000);
    return () => {
      clearInterval(interval);
      active.current?.abort();
    };
  }, [refresh]);

  return { data, error, refreshing, lastChecked, refresh };
}
