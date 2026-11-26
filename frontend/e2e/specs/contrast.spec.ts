import { expect, test } from "@playwright/test";
import { applyMatrixMode, installPlatformMocks } from "../mocks/fixtures";
import { auditThemeContrast } from "../helpers/contrast";

test.describe("WCAG 2.2 AA Contrast Gate", () => {
  test("meets >= 4.5:1 text and >= 3:1 control border contrast ratios", async ({
    page,
  }, testInfo) => {
    const theme = (testInfo.project.metadata?.theme as "dark" | "light") || "dark";
    const lang = (testInfo.project.metadata?.lang as "en" | "ar") || "en";

    await applyMatrixMode(page, theme, lang);
    await installPlatformMocks(page);

    await page.goto("/", { waitUntil: "domcontentloaded" });
    const samples = await auditThemeContrast(page);
    const failed = samples.filter((s) => !s.passed);
    expect(failed, `Contrast failures in ${theme}/${lang}: ${JSON.stringify(failed)}`).toEqual([]);
  });
});
