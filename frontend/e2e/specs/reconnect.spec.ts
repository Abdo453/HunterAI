import { expect, test } from "@playwright/test";
import { applyMatrixMode, installPlatformMocks } from "../mocks/fixtures";

test.describe("Canonical SSE Reconnect & ConnectionStatus", () => {
  test("recovers from transient SSE drop with backoff and surfaces ConnectionStatus pill", async ({
    page,
  }) => {
    await applyMatrixMode(page, "dark", "en");
    const mockState = await installPlatformMocks(page, { sseFailFirstAttempt: true });

    await page.goto("/", { waitUntil: "domcontentloaded" });
    const pill = page.getByTestId("connection-status-pill");
    await expect(pill).toBeVisible();

    // Wait for automatic retry reconnect to succeed
    await expect
      .poll(() => mockState.sseAttempts, { timeout: 6_000 })
      .toBeGreaterThanOrEqual(2);
  });
});
