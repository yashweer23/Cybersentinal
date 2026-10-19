import { defineConfig, loadEnv } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";
import { fileURLToPath } from "node:url";

const projectRoot = fileURLToPath(new URL("..", import.meta.url));

export default defineConfig(({ mode }) => {
  // Only load these non-secret values into Vite's server-side configuration.
  const env = loadEnv(mode, projectRoot, ["BACKEND_PORT", "FRONTEND_PORT"]);
  const target =
    process.env.BACKEND_PROXY_TARGET ||
    `http://127.0.0.1:${env.BACKEND_PORT || 8000}`;
  const proxy = Object.fromEntries(
    ["/api", "/docs", "/openapi.json", "/redoc"].map((path) => [
      path,
      { target, changeOrigin: true },
    ]),
  );
  return {
    plugins: [react(), tailwindcss()],
    server: {
      host: "0.0.0.0",
      port: Number(process.env.FRONTEND_DEV_PORT || env.FRONTEND_PORT || 5173),
      strictPort: true,
      proxy,
      watch: { usePolling: process.env.WATCH_USE_POLLING === "true" },
    },
    preview: { host: "127.0.0.1", port: 4173, strictPort: true, proxy },
  };
});
