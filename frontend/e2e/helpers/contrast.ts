import type { Page } from "@playwright/test";

export interface ContrastSample {
  name: string;
  fg: string;
  bg: string;
  ratio: number;
  minRequired: number;
  passed: boolean;
}

/**
 * WCAG 2.2 AA contrast verifier computing luminance contrast ratios directly from
 * resolved Obsidian Dark / Paper Light CSS variables in the live browser DOM.
 */
export async function auditThemeContrast(page: Page): Promise<ContrastSample[]> {
  return page.evaluate(() => {
    function parseRgbTriplet(raw: string): [number, number, number] {
      const nums = raw
        .trim()
        .replace(/[^\d.,\s]/g, " ")
        .split(/[\s,]+/)
        .map((n) => Number.parseFloat(n))
        .filter((n) => Number.isFinite(n));
      return [nums[0] ?? 0, nums[1] ?? 0, nums[2] ?? 0];
    }

    function relativeLuminance([r, g, b]: [number, number, number]): number {
      const linear = [r, g, b].map((c) => {
        const s = c / 255;
        return s <= 0.03928 ? s / 12.92 : Math.pow((s + 0.055) / 1.055, 2.4);
      });
      return 0.2126 * linear[0] + 0.7152 * linear[1] + 0.0722 * linear[2];
    }

    function contrastRatio(c1: [number, number, number], c2: [number, number, number]): number {
      const l1 = relativeLuminance(c1);
      const l2 = relativeLuminance(c2);
      const lighter = Math.max(l1, l2);
      const darker = Math.min(l1, l2);
      return Number(((lighter + 0.05) / (darker + 0.05)).toFixed(2));
    }

    const cs = window.getComputedStyle(document.documentElement);
    const readVar = (name: string) => cs.getPropertyValue(name).trim();

    const bgCanvas = parseRgbTriplet(readVar("--bg-canvas"));
    const bgSurface = parseRgbTriplet(readVar("--bg-surface"));
    const bgInset = parseRgbTriplet(readVar("--bg-inset"));

    const checks: Array<{ name: string; fgVar: string; bg: [number, number, number]; bgName: string; min: number }> = [
      { name: "Primary text on surface", fgVar: "--text-primary", bg: bgSurface, bgName: "--bg-surface", min: 4.5 },
      { name: "Secondary text on surface", fgVar: "--text-secondary", bg: bgSurface, bgName: "--bg-surface", min: 4.5 },
      { name: "Muted text on canvas", fgVar: "--text-muted", bg: bgCanvas, bgName: "--bg-canvas", min: 4.5 },
      { name: "Primary accent on surface", fgVar: "--accent-primary", bg: bgSurface, bgName: "--bg-surface", min: 4.5 },
      { name: "Danger accent on surface", fgVar: "--accent-danger", bg: bgSurface, bgName: "--bg-surface", min: 4.5 },
      { name: "Success accent on surface", fgVar: "--accent-success", bg: bgSurface, bgName: "--bg-surface", min: 4.5 },
      { name: "Warning accent on surface", fgVar: "--accent-warning", bg: bgSurface, bgName: "--bg-surface", min: 4.5 },
      { name: "Control border-strong on inset (WCAG 1.4.11)", fgVar: "--border-strong", bg: bgInset, bgName: "--bg-inset", min: 3.0 },
    ];

    return checks.map((chk) => {
      const fg = parseRgbTriplet(readVar(chk.fgVar));
      const ratio = contrastRatio(fg, chk.bg);
      return {
        name: chk.name,
        fg: `rgb(${fg.join(" ")})`,
        bg: `rgb(${chk.bg.join(" ")})`,
        ratio,
        minRequired: chk.min,
        passed: ratio >= chk.min,
      };
    });
  });
}
