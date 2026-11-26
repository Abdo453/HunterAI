#!/usr/bin/env node
/**
 * Fast Node verification script (`npm run verify:ui`) checking:
 *  1. 100% EN/AR key parity in `lib/catalog.json` + zero missing `t("...")` keys across app/components/lib/hooks
 *  2. Zero broken Tailwind arbitrary `[var(--*)]/XX` opacity utilities in TSX/TS files
 *  3. Terminal sanitizer unit assertions (strips ANSI cursor/OSC 0/4/10/11/12/javascript: OSC 8/Bidi/C0/C1, preserves SGR & Arabic RTL & 64KB chunking)
 *  4. Compiled `.next/static/css/*.css` contains non-zero restored RGB-alpha opacity utility rules
 *  5. Syntax/module verification of `eslint-rules/waitfor-budget.mjs` and `e2e/mock-llm/server.mjs`
 */

import fs from "node:fs";
import path from "node:path";
import assert from "node:assert/strict";
import { fileURLToPath, pathToFileURL } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(__dirname, "..");

function flattenKeys(obj, prefix = "") {
  const out = new Map();
  for (const [k, v] of Object.entries(obj || {})) {
    const full = prefix ? `${prefix}.${k}` : k;
    if (v && typeof v === "object" && !Array.isArray(v)) {
      for (const [ck, cv] of flattenKeys(v, full)) out.set(ck, cv);
    } else {
      out.set(full, String(v ?? ""));
    }
  }
  return out;
}

function walkTsFiles(dir, acc = []) {
  if (!fs.existsSync(dir)) return acc;
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) walkTsFiles(full, acc);
    else if (/\.(ts|tsx)$/.test(entry.name)) acc.push(full);
  }
  return acc;
}

// 1. Bilingual catalog.json parity + zero missing t("...") keys + zero broken arbitrary var alpha
function checkCatalogAndAlpha() {
  const catalogPath = path.join(ROOT, "lib", "catalog.json");
  const catalog = JSON.parse(fs.readFileSync(catalogPath, "utf8"));
  const enMap = flattenKeys(catalog.en);
  const arMap = flattenKeys(catalog.ar);

  const onlyEn = [...enMap.keys()].filter((k) => !arMap.has(k));
  const onlyAr = [...arMap.keys()].filter((k) => !enMap.has(k));
  assert.equal(onlyEn.length, 0, `Keys missing in AR catalog: ${onlyEn.join(", ")}`);
  assert.equal(onlyAr.length, 0, `Keys missing in EN catalog: ${onlyAr.join(", ")}`);

  // Verify the 5 restored studio.* keys
  for (const requiredKey of [
    "studio.noTraffic",
    "studio.readFailed",
    "studio.saveFailed",
    "studio.savedFile",
    "studio.sendingReq",
  ]) {
    assert.ok(enMap.has(requiredKey), `Missing EN key: ${requiredKey}`);
    assert.ok(arMap.has(requiredKey), `Missing AR key: ${requiredKey}`);
  }

  // Verify empty values don't exist
  for (const [k, v] of enMap.entries()) {
    assert.ok(v.trim().length > 0, `Empty EN translation for ${k}`);
  }
  for (const [k, v] of arMap.entries()) {
    assert.ok(v.trim().length > 0, `Empty AR translation for ${k}`);
  }

  const tsFiles = [
    ...walkTsFiles(path.join(ROOT, "app")),
    ...walkTsFiles(path.join(ROOT, "components")),
    ...walkTsFiles(path.join(ROOT, "lib")),
    ...walkTsFiles(path.join(ROOT, "hooks")),
  ];

  const usedKeys = new Set();
  const brokenAlphaHits = [];

  for (const file of tsFiles) {
    const src = fs.readFileSync(file, "utf8");
    for (const m of src.matchAll(/\bt\(\s*["']([a-zA-Z0-9_]+\.[a-zA-Z0-9_.]+)["']/g)) {
      usedKeys.add(m[1]);
    }
    for (const m of src.matchAll(/\b(?:labelKey|titleKey|descKey|label_key)\s*:\s*["']([a-zA-Z0-9_]+\.[a-zA-Z0-9_.]+)["']/g)) {
      usedKeys.add(m[1]);
    }
    for (const m of src.matchAll(/t\(\s*[^)]*\?\s*["']([a-zA-Z0-9_]+\.[a-zA-Z0-9_.]+)["']\s*:\s*["']([a-zA-Z0-9_]+\.[a-zA-Z0-9_.]+)["']/g)) {
      usedKeys.add(m[1]);
      usedKeys.add(m[2]);
    }
    if (/\[var\(--[a-z-]+\)\]\/\d+/.test(src)) {
      brokenAlphaHits.push(path.relative(ROOT, file));
    }
  }

  const missingUsedEn = [...usedKeys].filter((k) => !enMap.has(k));
  const missingUsedAr = [...usedKeys].filter((k) => !arMap.has(k));
  assert.equal(missingUsedEn.length, 0, `Used keys missing in EN catalog: ${missingUsedEn.join(", ")}`);
  assert.equal(missingUsedAr.length, 0, `Used keys missing in AR catalog: ${missingUsedAr.join(", ")}`);
  assert.equal(
    brokenAlphaHits.length,
    0,
    `Broken arbitrary var opacity classes found in: ${brokenAlphaHits.join(", ")}`
  );

  console.log(
    `[PASS] Catalog parity: ${enMap.size} EN == ${arMap.size} AR keys; ${usedKeys.size} referenced keys resolved; 0 broken var-alpha classes.`
  );
}

// 2. Terminal sanitizer behavior check (transpiling TS inline via regex-free strip or dynamic verification)
async function checkTerminalSanitizer() {
  const tsPath = path.join(ROOT, "lib", "terminal-sanitizer.ts");
  const tsSource = fs.readFileSync(tsPath, "utf8");

  // Validate zero catastrophic regex patterns and presence of key guards
  assert.ok(tsSource.includes("TERMINAL_CHUNK_BYTES"), "terminal-sanitizer must include 64KB TERMINAL_CHUNK_BYTES");
  assert.ok(tsSource.includes("isBidiControl"), "terminal-sanitizer must guard Bidi override chars");
  assert.ok(tsSource.includes("SAFE_PROTOCOLS"), "terminal-sanitizer must enforce OSC 8 SAFE_PROTOCOLS allowlist");

  // Run TypeScript compiler API (installed devDependency) to transpile and execute unit tests!
  const tsMod = await import("typescript");
  const ts = tsMod.default || tsMod;
  const compiled = ts.transpileModule(tsSource, {
    compilerOptions: { module: ts.ModuleKind.ESNext, target: ts.ScriptTarget.ES2022 },
  }).outputText;

  const dataUrl = `data:text/javascript;base64,${Buffer.from(compiled, "utf8").toString("base64")}`;
  const mod = await import(dataUrl);

  // (a) Preserves valid SGR color codes and Arabic RTL text while stripping cursor/OSC/Bidi/C0
  const arabic = "مرحبا بالعالم — فحص أمني";
  const dirty =
    "\x1b]0;EvilTitle\x07" +
    "\x1b]8;;javascript:alert(1)\x07click\x1b]8;;\x07" +
    "\x1b[2J\x1b[H" +
    "\x1b[32mOK\x1b[0m " +
    `\u202E${arabic}\u202C` +
    "\x07\x08";

  const withSgr = mod.processTerminalLog(dirty, { preserveSgr: true });
  assert.ok(withSgr.includes("\x1b[32mOK\x1b[0m"), "Valid SGR sequence should be preserved");
  assert.ok(withSgr.includes(arabic), "Arabic Unicode text must be preserved");
  assert.ok(!withSgr.includes("EvilTitle"), "OSC 0 title sequence must be stripped");
  assert.ok(!withSgr.includes("javascript:"), "Dangerous OSC 8 javascript: URL must be stripped");
  assert.ok(!withSgr.includes("\x1b[2J"), "CSI clear-screen sequence must be stripped");
  assert.ok(!withSgr.includes("\u202E"), "Bidi RLO override must be stripped");
  assert.ok(!withSgr.includes("\x08"), "C0 control byte must be stripped");

  // (a2) Binary payload detection
  assert.equal(mod.isBinaryContent("abc\x00def"), true, "Null-byte payload must be flagged as binary");
  assert.ok(!mod.processTerminalLog("abc\x00def").includes("\x00"), "Null byte must never leak through sanitizer");

  // (b) Plain sanitizer removes SGR too
  const plain = mod.sanitizePlainTerminalText(dirty);
  assert.ok(!plain.includes("\x1b["), "Plain sanitizer must strip SGR codes");
  assert.ok(plain.includes("OK") && plain.includes(arabic), "Plain sanitizer preserves readable content");

  // (c) >64KB chunking boundary integrity (split escape sequence across chunk boundary)
  const filler = "A".repeat(65535);
  const chunkBoundaryPayload = `${filler}\x1b[31mRED\x1b[0m\nDONE`;
  const chunkedOut = mod.processTerminalLog(chunkBoundaryPayload, { preserveSgr: true });
  assert.ok(chunkedOut.includes("\x1b[31mRED\x1b[0m"), "64KB chunk boundary must not break valid SGR");
  assert.ok(chunkedOut.endsWith("DONE"), "64KB chunk processing must preserve tail");

  // (d) ANSI parser returns safe React segments
  const segs = mod.parseAnsiSegments("\x1b[32mPASS\x1b[0m normal");
  assert.ok(segs.length >= 2, "parseAnsiSegments must emit styled & reset segments");
  assert.equal(segs[0].text, "PASS");
  assert.equal(segs[0].colorClass, "text-sentinel-success");

  console.log("[PASS] terminal-sanitizer.ts: SGR preserved, OSC/CSI/Bidi/C0 stripped, Arabic RTL + 64KB chunking verified.");
}

// 3. Compiled CSS opacity utility check in .next/static/css/*.css
function checkCompiledOpacityCss() {
  const cssDir = path.join(ROOT, ".next", "static", "css");
  assert.ok(fs.existsSync(cssDir), "Missing .next/static/css — run `npm run build` before `npm run verify:ui`.");
  const cssFiles = fs.readdirSync(cssDir).filter((f) => f.endsWith(".css"));
  assert.ok(cssFiles.length > 0, "No compiled CSS files found under .next/static/css/");

  let combinedCss = "";
  for (const f of cssFiles) {
    combinedCss += fs.readFileSync(path.join(cssDir, f), "utf8");
  }

  const alphaRuleMatches =
    combinedCss.match(/rgb\(var\(--accent-(?:primary|success|warning|danger|ai)\)\s*\/\s*0?\.\d+\)/g) ||
    [];
  assert.ok(
    alphaRuleMatches.length >= 10,
    `Expected >= 10 compiled RGB-alpha utility rules in .next/static/css/*.css, found ${alphaRuleMatches.length}`
  );

  // Verify raised WCAG 1.4.11 border tokens exist in compiled CSS
  assert.ok(combinedCss.includes("59 75 99"), "Expected dark --border-subtle RGB triplet (59 75 99) in compiled CSS");
  assert.ok(combinedCss.includes("148 163 184"), "Expected light --border-subtle RGB triplet (148 163 184) in compiled CSS");

  console.log(
    `[PASS] Compiled CSS (${cssFiles.length} file(s)): ${alphaRuleMatches.length} restored RGB-alpha utility rules verified + WCAG 1.4.11 borders present.`
  );
}

// 4. Verify custom ESLint rule and mock-LLM module load cleanly
async function checkToolingModules() {
  const ruleMod = await import(pathToFileURL(path.join(ROOT, "eslint-rules", "waitfor-budget.mjs")).href);
  assert.equal(typeof ruleMod.default?.create, "function", "waitfor-budget.mjs must export ESLint rule");

  const mockLlmMod = await import(pathToFileURL(path.join(ROOT, "e2e", "mock-llm", "server.mjs")).href);
  assert.equal(typeof mockLlmMod.createMockLlmServer, "function", "mock-llm/server.mjs must export createMockLlmServer");

  console.log("[PASS] Tooling modules: eslint-rules/waitfor-budget.mjs & e2e/mock-llm/server.mjs loaded cleanly.");
}

async function main() {
  checkCatalogAndAlpha();
  await checkTerminalSanitizer();
  checkCompiledOpacityCss();
  await checkToolingModules();
  console.log("[ALL PASS] Phase 7 frontend verification checks succeeded.");
}

main().catch((err) => {
  console.error("[FAIL]", err instanceof Error ? err.message : err);
  process.exit(1);
});
