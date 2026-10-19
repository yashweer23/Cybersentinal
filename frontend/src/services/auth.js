import { api, authTransport, configureAuth, errorMessage } from "./api";

// Access credentials live only in memory. The browser owns the HTTP-only refresh cookie.
let accessToken = null;
let snapshot = { user: null, status: "loading", error: null };
let generation = 0;
let refreshFlight = null;
const listeners = new Set();
const guard = { "X-CSRF-Guard": "1" };
const channel =
  typeof BroadcastChannel === "function"
    ? new BroadcastChannel("cybersentinel-auth")
    : null;
const cookieLock = (action) =>
  navigator.locks
    ? navigator.locks.request("cybersentinel-auth-cookie", action)
    : action();
function publish(next) {
  snapshot = next;
  listeners.forEach((listener) => listener());
}
function accept(data) {
  accessToken = data.access_token;
  publish({ user: data.user, status: "authenticated", error: null });
}
export function expire() {
  generation += 1;
  accessToken = null;
  publish({ user: null, status: "anonymous", error: null });
}
export async function refreshSession() {
  if (refreshFlight) return refreshFlight;
  const current = generation;
  refreshFlight = cookieLock(async () => {
    // Another action may have signed out while this refresh waited for the cookie lock.
    if (current !== generation) throw new Error("Session changed");
    const { data } = await authTransport.post(
      "/auth/refresh",
      {},
      { headers: guard },
    );
    if (current === generation) accept(data);
    return data;
  })
    .catch((error) => {
      if (current === generation) {
        if ([401, 403].includes(error.response?.status)) expire();
        else
          publish({
            ...snapshot,
            status: snapshot.user ? "authenticated" : "error",
            error: errorMessage(error),
          });
      }
      throw error;
    })
    .finally(() => {
      refreshFlight = null;
    });
  return refreshFlight;
}
export async function bootstrapSession() {
  if (snapshot.user) return;
  // Wait out obsolete requests before recovering the current cookie session.
  if (refreshFlight) {
    try {
      await refreshFlight;
    } catch {
      /* State is handled above. */
    }
  }
  if (snapshot.status !== "loading" && snapshot.status !== "error") return;
  publish({ user: null, status: "loading", error: null });
  try {
    await refreshSession();
  } catch {
    /* The published state drives the error UI. */
  }
}
export async function retrySession() {
  publish({ user: null, status: "loading", error: null });
  await bootstrapSession();
}
export async function signIn(credentials) {
  const current = ++generation;
  const { data } = await cookieLock(() =>
    authTransport.post("/auth/login", credentials, { headers: guard }),
  );
  if (current === generation) {
    accept(data);
    channel?.postMessage("signed-in");
  }
  return data.user;
}
export async function registerAccount(details) {
  return authTransport.post("/auth/register", details, { headers: guard });
}
export async function refreshProfile() {
  const current = generation;
  const { data } = await api.get("/auth/me");
  if (current === generation && snapshot.user)
    publish({ user: data, status: "authenticated", error: null });
}
export async function signOut() {
  await cookieLock(() =>
    authTransport.post(
      "/auth/logout",
      {},
      {
        headers: {
          ...guard,
          ...(accessToken ? { Authorization: `Bearer ${accessToken}` } : {}),
        },
      },
    ),
  );
  expire();
  channel?.postMessage("signed-out");
}
export function reportProfileError(error) {
  if (snapshot.user)
    publish({
      ...snapshot,
      error: errorMessage(
        error,
        "Could not verify your current profile. Please retry.",
      ),
    });
}
channel?.addEventListener("message", (event) => {
  if (event.data === "signed-out") expire();
  if (event.data === "signed-in") {
    generation += 1;
    accessToken = null;
    publish({ user: null, status: "loading", error: null });
    void bootstrapSession();
  }
});
export const subscribe = (listener) => {
  listeners.add(listener);
  return () => listeners.delete(listener);
};
export const getSnapshot = () => snapshot;
configureAuth({ getToken: () => accessToken, refresh: refreshSession, expire });
