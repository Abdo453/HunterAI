import type { Page } from "@playwright/test";

export interface A11yAuditReport {
  violations: string[];
  checkedButtons: number;
  checkedLandmarks: number;
}

/**
 * WCAG 2.2 AA structural accessibility verifier for Obsidian Sentinel / Paper Slate.
 * Checks landmarks, icon-only accessible names, semantic buttons (no clickable role-less divs),
 * and document dir/lang consistency across EN LTR & AR RTL.
 */
export async function runStructuralA11yAudit(page: Page): Promise<A11yAuditReport> {
  return page.evaluate(() => {
    const violations: string[] = [];

    const html = document.documentElement;
    const lang = html.getAttribute("lang");
    const dir = html.getAttribute("dir");
    if (!lang || !["en", "ar"].includes(lang)) {
      violations.push(`Invalid <html lang="${lang}">`);
    }
    if ((lang === "ar" && dir !== "rtl") || (lang === "en" && dir !== "ltr")) {
      violations.push(`Mismatched dir="${dir}" for lang="${lang}"`);
    }

    const mainLandmark = document.querySelector("main#main-content");
    if (!mainLandmark) {
      violations.push("Missing <main id='main-content'> landmark");
    }

    const navLandmarks = document.querySelectorAll("nav[aria-label]");
    if (navLandmarks.length === 0) {
      violations.push("Missing labeled <nav aria-label> landmark");
    }

    const buttons = Array.from(document.querySelectorAll<HTMLButtonElement>("button"));
    let checkedButtons = 0;
    for (const btn of buttons) {
      const style = window.getComputedStyle(btn);
      if (style.display === "none" || style.visibility === "hidden") continue;
      checkedButtons += 1;
      const text = (btn.textContent || "").trim();
      const ariaLabel = (btn.getAttribute("aria-label") || "").trim();
      const ariaLabelledBy = (btn.getAttribute("aria-labelledby") || "").trim();
      const title = (btn.getAttribute("title") || "").trim();
      if (!text && !ariaLabel && !ariaLabelledBy && !title) {
        violations.push(`Icon-only button without accessible name: ${btn.outerHTML.slice(0, 120)}`);
      }
    }

    // Ensure no raw clickable <div> accordions are used in place of semantic <button aria-expanded>
    const divAccordions = document.querySelectorAll("div[aria-expanded]");
    if (divAccordions.length > 0) {
      violations.push(`Found ${divAccordions.length} non-semantic div[aria-expanded] elements`);
    }

    return {
      violations,
      checkedButtons,
      checkedLandmarks: (mainLandmark ? 1 : 0) + navLandmarks.length,
    };
  });
}
