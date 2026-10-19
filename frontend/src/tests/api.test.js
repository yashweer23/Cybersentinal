import { afterEach, expect, it, vi } from "vitest";
import { AxiosError } from "axios";
import { api, configureAuth } from "../services/api";
const original = api.defaults.adapter;
afterEach(() => {
  api.defaults.adapter = original;
  configureAuth(null);
});
function reject(config, status) {
  return Promise.reject(
    new AxiosError(
      "request failed",
      undefined,
      config,
      {},
      { status, data: { detail: "Denied" }, config, headers: {} },
    ),
  );
}
it("refreshes and retries a 401 with the current in-memory token", async () => {
  let token = "old",
    calls = 0;
  const refresh = vi.fn(async () => {
    token = "new";
  });
  const expire = vi.fn();
  configureAuth({ getToken: () => token, refresh, expire });
  api.defaults.adapter = async (config) => {
    calls++;
    if (calls === 1) return reject(config, 401);
    return {
      data: { authorization: config.headers.Authorization },
      status: 200,
      config,
      headers: {},
    };
  };
  const response = await api.get("/test");
  expect(response.data.authorization).toBe("Bearer new");
  expect(refresh).toHaveBeenCalledOnce();
  expect(expire).not.toHaveBeenCalled();
});
it("expires the session when a retried request still returns 401", async () => {
  const refresh = vi.fn(async () => {}),
    expire = vi.fn();
  configureAuth({ getToken: () => "token", refresh, expire });
  api.defaults.adapter = async (config) => reject(config, 401);
  await expect(api.get("/test")).rejects.toMatchObject({
    response: { status: 401 },
  });
  expect(refresh).toHaveBeenCalledOnce();
  expect(expire).toHaveBeenCalledOnce();
});
it("reports a 403 without refreshing or logging the user out", async () => {
  const refresh = vi.fn(),
    expire = vi.fn();
  configureAuth({ getToken: () => "token", refresh, expire });
  api.defaults.adapter = async (config) => reject(config, 403);
  await expect(api.get("/test")).rejects.toMatchObject({
    response: { status: 403 },
  });
  expect(refresh).not.toHaveBeenCalled();
  expect(expire).not.toHaveBeenCalled();
});

it.each([404, 422, 429, 500, 503])(
  "preserves a %s response without an authentication retry",
  async (status) => {
    const refresh = vi.fn(),
      expire = vi.fn();
    configureAuth({ getToken: () => "token", refresh, expire });
    const adapter = vi.fn(async (config) => reject(config, status));
    api.defaults.adapter = adapter;
    await expect(api.get("/test")).rejects.toMatchObject({
      response: { status },
    });
    expect(adapter).toHaveBeenCalledOnce();
    expect(refresh).not.toHaveBeenCalled();
    expect(expire).not.toHaveBeenCalled();
  },
);
it("preserves network failure without an authentication retry", async () => {
  const refresh = vi.fn(),
    expire = vi.fn();
  configureAuth({ getToken: () => "token", refresh, expire });
  api.defaults.adapter = async (config) => {
    throw new AxiosError("Network Error", "ERR_NETWORK", config);
  };
  await expect(api.get("/test")).rejects.toMatchObject({ code: "ERR_NETWORK" });
  expect(refresh).not.toHaveBeenCalled();
  expect(expire).not.toHaveBeenCalled();
});
