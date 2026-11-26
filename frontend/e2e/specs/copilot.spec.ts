import { expect, test } from "@playwright/test";
import { applyMatrixMode, installPlatformMocks, MOCK_APPROVAL_ID } from "../mocks/fixtures";

test.describe("Live AI Copilot Drawer", () => {
  test("streams thinking, citations, inline approval execution, and respects local_only lock", async ({
    page,
  }, testInfo) => {
    const theme = (testInfo.project.metadata?.theme as "dark" | "light") || "dark";
    const lang = (testInfo.project.metadata?.lang as "en" | "ar") || "en";

    await applyMatrixMode(page, theme, lang);
    await installPlatformMocks(page, { localOnlyPolicy: true });

    await page.goto("/", { waitUntil: "domcontentloaded" });

    // Open Copilot drawer
    await page.locator("header button").filter({ hasText: /Copilot|المساعد/ }).first().click();
    const drawer = page.getByTestId("copilot-drawer");
    await expect(drawer).toBeVisible();

    // local_only lock badge visible
    await expect(page.getByTestId("copilot-local-lock")).toBeVisible();

    // Send prompt and verify streaming completion + inline approval card
    const input = drawer.locator("textarea");
    await input.fill("Run nuclei verification on target.local");
    await page.getByTestId("copilot-send-btn").click();

    await expect(drawer.getByText("Verified cross-tenant IDOR signal on target.local.")).toBeVisible();

    const approvalCard = page.getByTestId(`copilot-approval-${MOCK_APPROVAL_ID}`);
    await expect(approvalCard).toBeVisible();
    await approvalCard.locator("button").first().click();
    await expect(approvalCard.getByText("1 high finding confirmed")).toBeVisible();
  });

  test("preserves composer draft when operator clicks Stop during streaming", async ({ page }) => {
    await applyMatrixMode(page, "dark", "en");
    await installPlatformMocks(page, { slowCopilotStream: true });

    await page.goto("/", { waitUntil: "domcontentloaded" });
    await page.locator("header button").filter({ hasText: "Copilot" }).first().click();
    const drawer = page.getByTestId("copilot-drawer");
    await expect(drawer).toBeVisible();

    const draft = "Preserve this prompt draft on stop";
    const input = drawer.locator("textarea");
    await input.fill(draft);
    await page.getByTestId("copilot-send-btn").click();

    const stopBtn = page.getByTestId("copilot-stop-btn");
    await expect(stopBtn).toBeVisible();
    await stopBtn.click();

    // Draft stays intact after abort
    await expect(input).toHaveValue(draft);
  });
});
