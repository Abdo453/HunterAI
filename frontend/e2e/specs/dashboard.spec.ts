import { expect, test } from "@playwright/test";
import { applyMatrixMode, installPlatformMocks, MOCK_RUN_ID } from "../mocks/fixtures";

test.describe("Unified Dashboard & 4-Way Matrix", () => {
  test("renders overview with hardware, budget, split mission workspace, and zero URL query pollution", async ({
    page,
  }, testInfo) => {
    const theme = (testInfo.project.metadata?.theme as "dark" | "light") || "dark";
    const lang = (testInfo.project.metadata?.lang as "en" | "ar") || "en";

    await applyMatrixMode(page, theme, lang);
    await installPlatformMocks(page);

    await page.goto("/", { waitUntil: "domcontentloaded" });

    // Pre-hydration script must align dir/lang/theme immediately
    const html = page.locator("html");
    await expect(html).toHaveAttribute("dir", lang === "ar" ? "rtl" : "ltr");
    await expect(html).toHaveAttribute("lang", lang);
    await expect(html).toHaveAttribute("data-theme", theme);

    // Core unified cards render real telemetry
    await expect(page.getByTestId("hardware-telemetry-card")).toBeVisible();
    await expect(page.getByTestId("token-cost-panel")).toBeVisible();
    await expect(page.getByTestId("mission-split-workspace")).toBeVisible();
    await expect(page.getByTestId("task-subtask-tree")).toBeVisible();

    // Normalized 0..1 -> 45% progress display & Recover trigger present
    await expect(page.getByText(MOCK_RUN_ID)).toBeVisible();
    await expect(page.getByText("(45%)")).toBeVisible();

    // URL must not be polluted with ?theme= or ?lang=
    expect(page.url()).not.toContain("theme=");
    expect(page.url()).not.toContain("lang=");
  });

  test("renders Evidence Court 7-state workbench and Vuln Intel panel on /findings", async ({
    page,
  }, testInfo) => {
    const theme = (testInfo.project.metadata?.theme as "dark" | "light") || "dark";
    const lang = (testInfo.project.metadata?.lang as "en" | "ar") || "en";

    await applyMatrixMode(page, theme, lang);
    await installPlatformMocks(page);

    await page.goto("/findings", { waitUntil: "domcontentloaded" });
    await expect(page.getByTestId("evidence-court-workbench")).toBeVisible();
    await expect(page.getByTestId("vuln-intel-panel")).toBeVisible();
    await expect(page.getByText("CVE-2025-1001")).toBeVisible();
  });
});
