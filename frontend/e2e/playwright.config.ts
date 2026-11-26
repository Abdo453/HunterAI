import { defineConfig, devices } from "@playwright/test";

const BASE_URL = process.env.E2E_BASE_URL || "http://127.0.0.1:3000";

export default defineConfig({
  testDir: "./specs",
  fullyParallel: true,
  forbidOnly: Boolean(process.env.CI),
  retries: process.env.CI ? 1 : 0,
  workers: process.env.CI ? 2 : undefined,
  timeout: 30_000,
  expect: {
    timeout: 8_000,
  },
  reporter: [["list"]],
  use: {
    baseURL: BASE_URL,
    trace: "on-first-retry",
    screenshot: "only-on-failure",
  },
  projects: [
    {
      name: "obsidian-dark-en",
      use: { ...devices["Desktop Chrome"], viewport: { width: 1366, height: 860 } },
      metadata: { theme: "dark", lang: "en" },
    },
    {
      name: "obsidian-dark-ar",
      use: { ...devices["Desktop Chrome"], viewport: { width: 1366, height: 860 } },
      metadata: { theme: "dark", lang: "ar" },
    },
    {
      name: "paper-light-en",
      use: { ...devices["Desktop Chrome"], viewport: { width: 1366, height: 860 } },
      metadata: { theme: "light", lang: "en" },
    },
    {
      name: "paper-light-ar",
      use: { ...devices["Desktop Chrome"], viewport: { width: 1366, height: 860 } },
      metadata: { theme: "light", lang: "ar" },
    },
  ],
  webServer: process.env.E2E_SKIP_SERVER
    ? undefined
    : {
        command: "npm run start",
        url: BASE_URL,
        reuseExistingServer: true,
        timeout: 60_000,
        env: {
          ...process.env,
          NEXT_PUBLIC_HUNTER_STREAM_SAME_ORIGIN: "1",
        },
      },
});
