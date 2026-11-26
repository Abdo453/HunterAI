import { expect, test } from "@playwright/test";
import { applyMatrixMode, installPlatformMocks } from "../mocks/fixtures";
import { runStructuralA11yAudit } from "../helpers/a11y";

test.describe("WCAG 2.2 AA Accessibility & Keyboard Navigation", () => {
  test("passes structural a11y audit and CommandPalette Escape focus handling", async ({
    page,
  }, testInfo) => {
    const theme = (testInfo.project.metadata?.theme as "dark" | "light") || "dark";
    const lang = (testInfo.project.metadata?.lang as "en" | "ar") || "en";

    await applyMatrixMode(page, theme, lang);
    await installPlatformMocks(page);

    await page.goto("/", { waitUntil: "domcontentloaded" });
    const report = await runStructuralA11yAudit(page);
    expect(report.checkedLandmarks).toBeGreaterThanOrEqual(2);
    expect(report.violations).toEqual([]);

    // Open CommandPalette with Ctrl+K and close with Escape
    await page.keyboard.press("Control+k");
    const dialog = page.locator("div[role='dialog'][aria-modal='true']").first();
    await expect(dialog).toBeVisible();
    await page.keyboard.press("Escape");
    await expect(dialog).toBeHidden();
  });
});
