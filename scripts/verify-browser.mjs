// Read-only acceptance against a local application. Login/logout create/revoke sessions.
import assert from "node:assert/strict";
import { writeFile } from "node:fs/promises";
import { pathToFileURL } from "node:url";
const { chromium } = await import(
  process.env.PLAYWRIGHT_MODULE
    ? pathToFileURL(process.env.PLAYWRIGHT_MODULE).href
    : "playwright"
);
const base = process.env.CS_SMOKE_BASE_URL || "http://localhost:5173";
assert(
  ["localhost", "127.0.0.1", "[::1]"].includes(new URL(base).hostname),
  "Use a loopback application URL",
);
const paths = [
  "/",
  "/incidents",
  "/events",
  "/threat-intelligence",
  "/analytics",
  "/ai-analyst",
  "/rules",
  "/health",
  "/settings",
];
const errors = [],
  violations = [],
  badResponses = [],
  results = [];
const browser = await chromium.launch({
  headless: true,
  ...(process.env.PLAYWRIGHT_CHROMIUM_EXECUTABLE
    ? { executablePath: process.env.PLAYWRIGHT_CHROMIUM_EXECUTABLE }
    : {}),
  args:
    process.env.CS_SMOKE_NO_SANDBOX === "1"
      ? [
          "--no-sandbox",
          "--disable-gpu",
          "--disable-dev-shm-usage",
          "--no-zygote",
        ]
      : [],
});
try {
  for (const role of ["ADMIN", "ANALYST", "VIEWER"]) {
    const username = process.env[`CS_SMOKE_${role}_USERNAME`];
    const password =
      process.env[`CS_SMOKE_${role}_PASSWORD`] || process.env.CS_SMOKE_PASSWORD;
    assert(
      username && password,
      `Provide ${role} smoke credentials through environment variables`,
    );
    const context = await browser.newContext({
        viewport: { width: 1440, height: 1000 },
      }),
      page = await context.newPage();
    page.on("pageerror", (e) => errors.push({ role, message: e.message }));
    page.on("console", (m) => {
      if (/Content Security Policy|Refused to/.test(m.text()))
        violations.push({ role, message: m.text() });
    });
    page.on("response", (r) => {
      const path = new URL(r.url()).pathname;
      if (
        path.startsWith("/api/") &&
        r.status() >= 400 &&
        !(path === "/api/auth/refresh" && r.status() === 401)
      )
        badResponses.push({ role, path, status: r.status() });
    });
    await page.goto(base + "/analytics");
    await page.getByLabel("Username", { exact: true }).fill(username);
    await page.getByLabel("Password", { exact: true }).fill(password);
    await page.getByRole("button", { name: "Sign in", exact: true }).click();
    await page.getByRole("button", { name: "Sign out", exact: true }).waitFor();
    let incidentPath;
    for (const path of paths) {
      // Exercise client routing without turning every navigation into a refresh
      // login. Explicit deep links below still verify Nginx SPA fallback.
      await page.locator(`nav a[href="${path}"]`).click();
      await page.waitForURL((url) => url.pathname === path);
      await page.locator("main h1").waitFor();
      await page.waitForFunction(
        () => !document.querySelector('[aria-label="Loading data"]'),
      );
      if (path === "/incidents") {
        const link = page.locator('main a[href^="/incidents/"]').first();
        await link.waitFor();
        incidentPath = await link.getAttribute("href");
      }
      assert.equal(
        await page.locator('main [role="alert"]').count(),
        0,
        `${role} ${path} showed an error`,
      );
    }
    assert(
      incidentPath,
      "Seed at least one incident for investigation coverage",
    );
    const detailResponse = await page.goto(base + incidentPath);
    assert.equal(detailResponse.status(), 200);
    await page.locator("main h1").waitFor();
    await page.waitForFunction(
      () => !document.querySelector('[aria-label="Loading data"]'),
    );
    assert.equal(await page.locator('main [role="alert"]').count(), 0);
    const adminResponse = await page.goto(base + "/admin");
    assert.equal(adminResponse.status(), 200);
    await page
      .getByRole("heading", {
        name:
          role === "ADMIN" ? "User access" : "Administrator access required.",
      })
      .waitFor();
    await page.getByRole("button", { name: "Sign out", exact: true }).click();
    await page.getByRole("button", { name: "Sign in", exact: true }).waitFor();
    results.push({
      role,
      pages: [...paths, "incident investigation", "/admin"],
      login: "passed",
      logout: "passed",
    });
    await context.close();
  }
  assert.deepEqual(errors, []);
  assert.deepEqual(violations, []);
  assert.deepEqual(badResponses, []);
  await writeFile(
    process.env.CS_SMOKE_OUTPUT || "browser-results.json",
    JSON.stringify(
      {
        results,
        page_errors: errors,
        csp_violations: violations,
        unexpected_api_errors: badResponses,
      },
      null,
      2,
    ),
  );
  console.log("Browser acceptance passed for ADMIN, ANALYST and VIEWER.");
} finally {
  await browser.close();
}
