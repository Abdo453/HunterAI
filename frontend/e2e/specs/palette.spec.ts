import { expect, test } from "@playwright/test";
import { applyMatrixMode, installPlatformMocks } from "../mocks/fixtures";

test.describe("Obsidian Sentinel & Paper Slate Palette / Opacity Utilities", () => {
  test("resolves RGB channel triplets and emits alpha opacity styles", async ({
    page,
  }, testInfo) => {
    const theme = (testInfo.project.metadata?.theme as "dark" | "light") || "dark";
    const lang = (testInfo.project.metadata?.lang as "en" | "ar") || "en";

    await applyMatrixMode(page, theme, lang);
    await installPlatformMocks(page);

    await page.goto("/", { waitUntil: "domcontentloaded" });

    const tokenCheck = await page.evaluate(() => {
      const cs = window.getComputedStyle(document.documentElement);
      const accentPrimary = cs.getPropertyValue("--accent-primary").trim();
      const borderSubtle = cs.getPropertyValue("--border-subtle").trim();

      let alphaRulesCount = 0;
      for (const sheet of Array.from(document.styleSheets)) {
        try {
          for (const rule of Array.from(sheet.cssRules || [])) {
            if (rule.cssText.includes("rgb(var(--accent-") && rule.cssText.includes("/")) {
              alphaRulesCount += 1;
            }
          }
        } catch {
          // Cross-origin stylesheet ignored
        }
      }
      return { accentPrimary, borderSubtle, alphaRulesCount };
    });

    expect(tokenCheck.accentPrimary).toMatch(/^\d+\s+\d+\s+\d+$/);
    expect(tokenCheck.borderSubtle).toMatch(/^\d+\s+\d+\s+\d+$/);
    expect(tokenCheck.alphaRulesCount).toBeGreaterThanOrEqual(5);
  });
});
