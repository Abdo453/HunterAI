"use client";

import React, { useEffect, useMemo, useState } from "react";
import {
  ShieldAlert,
  CheckCircle2,
  Search,
  ArrowUpDown,
  Download,
  FileText,
  X,
  Copy,
  Check,
  ExternalLink,
} from "lucide-react";
import { FindingRecord, usePlatform } from "@/lib/platform-context";
import { useI18n } from "@/lib/i18n";
import { renderSafeMarkdown, safeHref } from "@/lib/sanitize";

type SeverityFilter = "ALL" | "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";
type SortField = "cvss" | "confidence";

const SEVERITY_LEVELS: SeverityFilter[] = [
  "ALL",
  "CRITICAL",
  "HIGH",
  "MEDIUM",
  "LOW",
  "INFO",
];

function getSeverityBadgeClass(severity: string): string {
  switch (severity.toUpperCase()) {
    case "CRITICAL":
      return "bg-[var(--accent-danger-bg)] text-sentinel-danger border-[var(--accent-danger)]/40";
    case "HIGH":
      return "bg-[var(--accent-warning-bg)] text-sentinel-warning border-[var(--accent-warning)]/40";
    case "MEDIUM":
      return "bg-[var(--accent-primary-bg)] text-sentinel-primary border-[var(--accent-primary)]/40";
    default:
      return "bg-inset text-ink-secondary border-border-subtle";
  }
}

function triggerDownload(filename: string, content: string, mimeType: string) {
  const blob = new Blob([content], { type: mimeType });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

function buildFindingMarkdown(items: FindingRecord[]): string {
  const lines: string[] = [
    "# ARTEX-Pro Vulnerability Findings Report",
    "",
    `Generated: ${new Date().toISOString()}`,
    `Total Findings: ${items.length}`,
    "",
  ];
  for (const f of items) {
    lines.push(`## [${f.severity}] ${f.title}`);
    lines.push(`- **ID:** \`${f.id}\``);
    lines.push(`- **Vulnerability Class:** \`${f.vuln_class}\``);
    lines.push(`- **CVSS Score:** ${f.cvss_score.toFixed(1)} | **Confidence:** ${Math.round(f.confidence * 100)}%`);
    lines.push(`- **Status:** ${f.status}`);
    if (f.endpoint) lines.push(`- **Endpoint:** \`${f.endpoint}\``);
    if (f.evidence) {
      lines.push("");
      lines.push("### Evidence / PoC");
      lines.push("```");
      lines.push(f.evidence);
      lines.push("```");
    }
    lines.push("");
  }
  return lines.join("\n");
}

function buildFindingDetailMarkdown(f: FindingRecord): string {
  const parts: string[] = [];
  const desc = f.poc_details?.description;
  if (typeof desc === "string" && desc.trim()) {
    parts.push(desc.trim());
  }
  if (f.evidence && f.evidence.trim()) {
    parts.push(`### Evidence\n\`\`\`\n${f.evidence.trim()}\n\`\`\``);
  }
  const curl = f.poc_details?.curl_command;
  if (typeof curl === "string" && curl.trim() && curl.trim() !== f.evidence.trim()) {
    parts.push(`### Reproducible cURL\n\`\`\`bash\n${curl.trim()}\n\`\`\``);
  }
  if (f.poc_script && f.poc_script.trim()) {
    parts.push(`### PoC Script\n\`\`\`\n${f.poc_script.trim()}\n\`\`\``);
  }
  return parts.join("\n\n");
}

export default function FindingsTable() {
  const { findings, inspectedFinding, setInspectedFinding } = usePlatform();
  const { t } = useI18n();

  const [severityFilter, setSeverityFilter] = useState<SeverityFilter>("ALL");
  const [search, setSearch] = useState<string>("");
  const [sortBy, setSortBy] = useState<SortField>("cvss");
  const [sortDesc, setSortDesc] = useState<boolean>(true);
  const [copiedId, setCopiedId] = useState<string | null>(null);

  useEffect(() => {
    if (!inspectedFinding) return;
    const onKeyDown = (ev: KeyboardEvent) => {
      if (ev.key === "Escape") {
        setInspectedFinding(null);
      }
    };
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, [inspectedFinding, setInspectedFinding]);

  const countsBySeverity = useMemo(() => {
    const counts: Record<SeverityFilter, number> = {
      ALL: findings.length,
      CRITICAL: 0,
      HIGH: 0,
      MEDIUM: 0,
      LOW: 0,
      INFO: 0,
    };
    for (const f of findings) {
      const sev = f.severity.toUpperCase() as SeverityFilter;
      if (sev in counts) {
        counts[sev] += 1;
      } else {
        counts.INFO += 1;
      }
    }
    return counts;
  }, [findings]);

  const filteredFindings = useMemo(() => {
    const q = search.trim().toLowerCase();
    const list = findings.filter((f) => {
      if (severityFilter !== "ALL" && f.severity.toUpperCase() !== severityFilter) {
        return false;
      }
      if (!q) return true;
      return (
        f.title.toLowerCase().includes(q) ||
        f.vuln_class.toLowerCase().includes(q) ||
        f.endpoint.toLowerCase().includes(q) ||
        f.status.toLowerCase().includes(q)
      );
    });
    return [...list].sort((a, b) => {
      const va = sortBy === "cvss" ? a.cvss_score : a.confidence;
      const vb = sortBy === "cvss" ? b.cvss_score : b.confidence;
      return sortDesc ? vb - va : va - vb;
    });
  }, [findings, severityFilter, search, sortBy, sortDesc]);

  const toggleSort = (field: SortField) => {
    if (sortBy === field) {
      setSortDesc((prev) => !prev);
    } else {
      setSortBy(field);
      setSortDesc(true);
    }
  };

  const handleCopy = async (text: string, id: string) => {
    try {
      await navigator.clipboard.writeText(text);
      setCopiedId(id);
      window.setTimeout(() => setCopiedId(null), 1500);
    } catch {
      // Ignore clipboard failure
    }
  };

  const sanitizedDrawerHtml = useMemo(() => {
    if (!inspectedFinding) return "";
    const md = buildFindingDetailMarkdown(inspectedFinding);
    return md ? renderSafeMarkdown(md) : "";
  }, [inspectedFinding]);

  const endpointHref = inspectedFinding ? safeHref(inspectedFinding.endpoint, "#") : "#";

  return (
    <section
      aria-labelledby="findings-heading"
      className="sentinel-surface p-4 flex flex-col gap-3 h-[540px]"
    >
      {/* Header */}
      <div className="flex flex-wrap items-center justify-between gap-2 pb-3 border-b border-border-subtle">
        <div className="flex items-center gap-2">
          <ShieldAlert className="w-4 h-4 text-sentinel-warning" />
          <h2 id="findings-heading" className="text-sm font-semibold text-ink-primary">
            {t("findings.title")}
          </h2>
          <span className="text-xs font-mono tabular-nums px-2 py-0.5 rounded bg-elevated border border-border-subtle text-ink-secondary">
            {filteredFindings.length}
          </span>
        </div>

        <div className="flex items-center gap-1.5">
          <button
            type="button"
            disabled={filteredFindings.length === 0}
            onClick={() =>
              triggerDownload(
                "artex-findings.json",
                JSON.stringify(filteredFindings, null, 2),
                "application/json"
              )
            }
            className="h-8 px-2.5 rounded border border-border-subtle bg-elevated hover:border-border-strong text-xs text-ink-secondary hover:text-ink-primary flex items-center gap-1 disabled:opacity-40"
          >
            <Download className="w-3.5 h-3.5" />
            <span>{t("findings.downloadJson")}</span>
          </button>

          <button
            type="button"
            disabled={filteredFindings.length === 0}
            onClick={() =>
              triggerDownload(
                "artex-findings.md",
                buildFindingMarkdown(filteredFindings),
                "text/markdown;charset=utf-8"
              )
            }
            className="h-8 px-2.5 rounded border border-border-subtle bg-elevated hover:border-border-strong text-xs text-ink-secondary hover:text-ink-primary flex items-center gap-1 disabled:opacity-40"
          >
            <FileText className="w-3.5 h-3.5" />
            <span>{t("findings.downloadMd")}</span>
          </button>
        </div>
      </div>

      {/* Filters & Sort */}
      <div className="flex flex-col gap-2">
        <div className="flex flex-wrap items-center gap-1.5">
          {SEVERITY_LEVELS.map((sev) => (
            <button
              key={sev}
              type="button"
              onClick={() => setSeverityFilter(sev)}
              aria-pressed={severityFilter === sev}
              className={`px-2 py-1 rounded text-[11px] font-mono tabular-nums border transition-colors ${
                severityFilter === sev
                  ? "border-sentinel-primary bg-[var(--accent-primary-bg)] text-sentinel-primary"
                  : "border-border-subtle bg-elevated text-ink-muted hover:text-ink-primary"
              }`}
            >
              {sev === "ALL" ? t("common.all") : sev} ({countsBySeverity[sev]})
            </button>
          ))}
        </div>

        <div className="flex flex-wrap items-center gap-2">
          <div className="relative flex-1 min-w-[180px]">
            <Search className="w-3.5 h-3.5 text-ink-muted absolute top-1/2 -translate-y-1/2 start-2.5 pointer-events-none" />
            <input
              type="search"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder={t("findings.searchPlaceholder")}
              aria-label={t("findings.searchPlaceholder")}
              className="w-full h-8 ps-8 pe-3 rounded bg-inset border border-border-subtle text-xs text-ink-primary placeholder:text-ink-muted"
            />
          </div>

          <button
            type="button"
            onClick={() => toggleSort("cvss")}
            aria-pressed={sortBy === "cvss"}
            className={`h-8 px-2.5 rounded border text-xs font-mono flex items-center gap-1 ${
              sortBy === "cvss"
                ? "border-sentinel-primary bg-[var(--accent-primary-bg)] text-sentinel-primary"
                : "border-border-subtle bg-elevated text-ink-secondary"
            }`}
          >
            <ArrowUpDown className="w-3 h-3" />
            <span>{t("findings.sortByCvss")}</span>
          </button>

          <button
            type="button"
            onClick={() => toggleSort("confidence")}
            aria-pressed={sortBy === "confidence"}
            className={`h-8 px-2.5 rounded border text-xs font-mono flex items-center gap-1 ${
              sortBy === "confidence"
                ? "border-sentinel-primary bg-[var(--accent-primary-bg)] text-sentinel-primary"
                : "border-border-subtle bg-elevated text-ink-secondary"
            }`}
          >
            <ArrowUpDown className="w-3 h-3" />
            <span>{t("findings.sortByConfidence")}</span>
          </button>
        </div>
      </div>

      {/* Findings List */}
      {filteredFindings.length === 0 ? (
        <div className="flex-1 flex flex-col items-center justify-center text-ink-muted text-center px-4">
          <CheckCircle2 className="w-9 h-9 mb-2 text-sentinel-success opacity-50" />
          <p className="text-sm font-medium text-ink-secondary">{t("findings.emptyTitle")}</p>
          <p className="text-xs text-ink-muted mt-1">{t("findings.emptySub")}</p>
        </div>
      ) : (
        <div className="flex-1 overflow-y-auto space-y-2 pe-1">
          {filteredFindings.map((f, idx) => (
            <button
              key={`${f.id || f.title || "finding"}-${idx}`}
              type="button"
              onClick={() => setInspectedFinding(f)}
              className="w-full text-start p-3 rounded-md bg-elevated border border-border-subtle hover:border-border-strong transition-colors flex flex-col gap-1.5"
            >
              <div className="flex items-start justify-between gap-2 w-full">
                <div className="flex flex-wrap items-center gap-2 min-w-0">
                  <span
                    className={`ltr-isolate text-[11px] font-mono tabular-nums px-2 py-0.5 rounded border font-semibold ${getSeverityBadgeClass(f.severity)}`}
                  >
                    {f.severity} {f.cvss_score.toFixed(1)}
                  </span>
                  <span className="font-semibold text-xs text-ink-primary truncate">
                    {f.title}
                  </span>
                </div>

                <span className="ltr-isolate text-[11px] font-mono tabular-nums px-2 py-0.5 rounded bg-inset text-sentinel-success border border-border-subtle shrink-0">
                  {f.status} · {Math.round(f.confidence * 100)}%
                </span>
              </div>

              <div className="flex flex-wrap items-center justify-between gap-2 text-xs font-mono text-ink-muted w-full">
                <span className="ltr-isolate truncate max-w-[72%] text-ink-secondary">
                  {f.endpoint || f.vuln_class}
                </span>
                <span className="ltr-isolate text-[11px] text-ink-muted">{f.vuln_class}</span>
              </div>
            </button>
          ))}
        </div>
      )}

      {/* Finding Detail Drawer */}
      {inspectedFinding && (
        <div
          className="fixed inset-0 z-50 flex justify-end bg-black/50 backdrop-blur-[1px]"
          onClick={() => setInspectedFinding(null)}
        >
          <div
            role="dialog"
            aria-modal="true"
            aria-labelledby="finding-drawer-title"
            className="w-full max-w-xl h-full bg-surface border-s border-border-subtle shadow-sentinelMd flex flex-col overflow-hidden"
            onClick={(e) => e.stopPropagation()}
          >
            <div className="px-5 py-4 border-b border-border-subtle flex items-start justify-between gap-3">
              <div className="min-w-0 space-y-1">
                <div className="flex items-center gap-2 flex-wrap">
                  <span
                    className={`ltr-isolate text-xs font-mono tabular-nums px-2 py-0.5 rounded border font-semibold ${getSeverityBadgeClass(inspectedFinding.severity)}`}
                  >
                    {inspectedFinding.severity} · CVSS {inspectedFinding.cvss_score.toFixed(1)}
                  </span>
                  <span className="text-xs font-mono px-2 py-0.5 rounded bg-elevated border border-border-subtle text-ink-secondary">
                    {inspectedFinding.status}
                  </span>
                </div>
                <h3 id="finding-drawer-title" className="text-base font-semibold text-ink-primary">
                  {inspectedFinding.title}
                </h3>
              </div>

              <button
                type="button"
                onClick={() => setInspectedFinding(null)}
                aria-label={t("common.close")}
                className="h-8 w-8 rounded border border-border-subtle bg-elevated text-ink-secondary hover:text-ink-primary flex items-center justify-center shrink-0"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <div className="flex-1 overflow-y-auto p-5 space-y-4">
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-xs">
                <div className="p-3 rounded-md bg-elevated border border-border-subtle space-y-1">
                  <div className="text-ink-muted">{t("findings.vulnClassLabel")}</div>
                  <div className="font-mono text-ink-primary ltr-isolate">
                    {inspectedFinding.vuln_class}
                  </div>
                </div>
                <div className="p-3 rounded-md bg-elevated border border-border-subtle space-y-1">
                  <div className="text-ink-muted">{t("findings.confidenceLabel")}</div>
                  <div className="font-mono tabular-nums text-ink-primary ltr-isolate">
                    {Math.round(inspectedFinding.confidence * 100)}%
                  </div>
                </div>
              </div>

              <div className="p-3 rounded-md bg-elevated border border-border-subtle space-y-1.5">
                <div className="flex items-center justify-between gap-2 text-xs text-ink-muted">
                  <span>{t("findings.endpointLabel")}</span>
                  <div className="flex items-center gap-2">
                    {inspectedFinding.endpoint && (
                      <button
                        type="button"
                        onClick={() => void handleCopy(inspectedFinding.endpoint, "ep")}
                        className="text-xs text-sentinel-primary hover:underline flex items-center gap-1"
                      >
                        {copiedId === "ep" ? <Check className="w-3 h-3" /> : <Copy className="w-3 h-3" />}
                        <span>{copiedId === "ep" ? t("common.copied") : t("common.copy")}</span>
                      </button>
                    )}
                    {endpointHref !== "#" && (
                      <a
                        href={endpointHref}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="text-xs text-sentinel-primary hover:underline flex items-center gap-1"
                      >
                        <span>{t("graph.openUrl")}</span>
                        <ExternalLink className="w-3 h-3" />
                      </a>
                    )}
                  </div>
                </div>
                <div className="font-mono text-xs text-ink-primary ltr-isolate break-all">
                  {inspectedFinding.endpoint || "—"}
                </div>
              </div>

              <div className="space-y-2">
                <div className="flex items-center justify-between">
                  <h4 className="text-xs font-semibold uppercase tracking-wider text-ink-muted">
                    {t("findings.evidenceLabel")}
                  </h4>
                  <button
                    type="button"
                    onClick={() =>
                      triggerDownload(
                        `finding-${inspectedFinding.id}.md`,
                        buildFindingMarkdown([inspectedFinding]),
                        "text/markdown;charset=utf-8"
                      )
                    }
                    className="h-7 px-2 rounded border border-border-subtle bg-elevated text-xs text-ink-secondary hover:text-ink-primary flex items-center gap-1"
                  >
                    <Download className="w-3 h-3" />
                    <span>{t("findings.downloadMd")}</span>
                  </button>
                </div>

                {sanitizedDrawerHtml ? (
                  <div
                    className="sentinel-prose p-3.5 rounded-md bg-elevated border border-border-subtle"
                    dangerouslySetInnerHTML={{ __html: sanitizedDrawerHtml }}
                  />
                ) : (
                  <div className="p-4 rounded-md bg-elevated border border-border-subtle text-xs text-ink-muted">
                    {t("findings.noEvidence")}
                  </div>
                )}
              </div>
            </div>
          </div>
        </div>
      )}
    </section>
  );
}
