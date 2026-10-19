import axios from "axios";

// Same-origin requests: the browser never receives Docker service hostnames or secrets.
const options = { baseURL: "/api", timeout: 15000, withCredentials: true };
export const api = axios.create(options);
export const authTransport = axios.create(options);
let auth;
export function configureAuth(callbacks) {
  auth = callbacks;
}

api.interceptors.request.use((config) => {
  const token = auth?.getToken();
  if (token) config.headers.Authorization = `Bearer ${token}`;
  else delete config.headers.Authorization;
  return config;
});
api.interceptors.response.use(
  (response) => response,
  async (error) => {
    const original = error.config;
    if (error.response?.status !== 401 || !auth || !original) throw error;
    if (original._authRetried) {
      auth.expire();
      throw error;
    }
    original._authRetried = true;
    await auth.refresh();
    return api(original);
  },
);

export function errorMessage(
  error,
  fallback = "Unable to reach the API. Please try again.",
) {
  const detail = error.response?.data?.detail;
  if (typeof detail === "string") return detail;
  if (Array.isArray(detail)) return detail.map((item) => item.msg).join(". ");
  return fallback;
}

export async function fetchHealth(signal) {
  const response = await api.get("/system/health", {
    signal,
    validateStatus: (status) => status === 200 || status === 503,
  });
  const body = response.data;
  if (
    !["healthy", "degraded"].includes(body?.status) ||
    !body?.services?.database
  ) {
    throw new Error("The API returned an unexpected health response.");
  }
  return body;
}
