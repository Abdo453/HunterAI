"use client";

import React, { useCallback, useEffect, useMemo, useState } from "react";
import {
  FileText,
  RefreshCw,
  Archive,
  X,
  Download,
  ShieldCheck,
  Loader2,
} from "lucide-react";
import FindingsTable from "@/components/FindingsTable";
import EvidenceCourtDrawer from "@/components/EvidenceCourtDrawer";
import VulnIntelPanel from "@/components/VulnIntelPanel";
import { EvidenceLedgerResponse } from "@/lib/api-types";
import { usePlatform } from "@/lib/platform-context";
import { useI18n } from "@/lib/i18n";
import { renderSafeMarkdown } from "@/lib/sanitize";
import { useFocusTrap } from "@/hooks/use-focus-trap";

interface ResultReportItem {
  id: string;
  title: string;
  severity: string;
  vulnerability_type: string;
  target: string;
  platform: string;
  classification: "CONFIRMED" | "SUSPECTED" | "FALSE_POSITIVE" | string;
  confidence: number;
  generated_at: string;
  summary: string;
  evidence: string;
  remediation: string;
  filename: string;
}

interface SessionSummary {
  id: string;
  target: string;
  mode: string;
  status: string;
  findings_count?: number;
}

interface EnhancedReportFile {
  filename: string;
  size_bytes: number;
  modified: string;
  is_master_dossier?: boolean;
}

interface SnapshotSummary {
  filename: string;
  snapshot_id: string;
  target: string;
  phase: string;
  coverage_pct: number;
  findings_count: number;
  modified: string;
}

export default function FindingsPage() {
  const { apiJson, hunterFetch, inspectedEvidenceId, setInspectedEvidenceId } = usePlatform();
  const { t } = useI18n();

  const [classificationFilter, setClassificationFilter] = useState<string>("ALL");
  const [results, setResults] = useState<ResultReportItem[]>([]);
  const [sessions, setSessions] = useState<SessionSummary[]>([]);
  const [reports, setReports] = useState<EnhancedReportFile[]>([]);
  const [snapshots, setSnapshots] = useState<SnapshotSummary[]>([]);
  const [ledger, setLedger] = useState<EvidenceLedgerResponse | null>(null);
  const [exportingKey, setExportingKey] = useState<string | null>(null);
  const [exportError, setExportError] = useState<string>("");

  const [openedDossier, setOpenedDossier] = useState<{ title: string; markdown: string } | null>(null);
  const [inspectedSnapshot, setInspectedSnapshot] = useState<SnapshotSummary | null>(null);

  const dossierTrapRef = useFocusTrap(Boolean(openedDossier), () => setOpenedDossier(null));
  const snapshotTrapRef = useFocusTrap(Boolean(inspectedSnapshot), () => setInspectedSnapshot(null));

  const loadAll = useCallback(async () => {
    const [resR, sessR, repR, snapR, ledR] = await Promise.all([
      apiJson<{ findings?: ResultReportItem[] }>("/api/control/results"),
      apiJson<SessionSummary[] | { sessions?: Array<SessionSummary | string> }>("/api/sessions"),
      apiJson<{ reports?: Array<EnhancedReportFile | string> }>("/api/enhanced/reports"),
      apiJson<{ snapshots?: Array<SnapshotSummary | string> }>("/api/enhanced/snapshots"),
      apiJson<EvidenceLedgerResponse>("/api/evidence/ledger"),
    ]);

    if (resR.ok && Array.isArray(resR.data?.findings)) {
      setResults(
        resR.data.findings
          .filter((item): item is ResultReportItem => Boolean(item && typeof item === "object"))
          .map((item, idx) => ({
            ...item,
            id: String(item.id || item.filename || item.title || `result-${idx}`),
          }))
      );
    }
    if (sessR.ok && sessR.data) {
      const rawSessions = Array.isArray(sessR.data)
        ? sessR.data
        : Array.isArray(sessR.data.sessions)
          ? sessR.data.sessions
          : [];
      const normalizedSessions = rawSessions
        .map((item: unknown): SessionSummary | null => {
          if (typeof item === "string" && item.trim()) {
            return { id: item.trim(), target: item.trim(), mode: "", status: "completed" };
          }
          if (item && typeof item === "object") {
            const obj = item as Record<string, unknown>;
            const id = String(obj.id || obj.session_id || obj.run_id || "").trim();
            if (!id) return null;
            return {
              id,
              target: String(obj.target || id),
              mode: String(obj.mode || ""),
              status: String(obj.status || "completed"),
              findings_count: typeof obj.findings_count === "number" ? obj.findings_count : 0,
            };
          }
          return null;
        })
        .filter((item): item is SessionSummary => item !== null);
      setSessions(normalizedSessions);
    }
    if (repR.ok && Array.isArray(repR.data?.reports)) {
      const normalizedReports = repR.data.reports
        .map((item: unknown): EnhancedReportFile | null => {
          if (typeof item === "string" && item.trim()) {
            return { filename: item.trim(), size_bytes: 0, modified: "" };
          }
          if (item && typeof item === "object") {
            const obj = item as Record<string, unknown>;
            const filename = String(obj.filename || obj.name || "").trim();
            if (!filename) return null;
            return {
              filename,
              size_bytes: Number(obj.size_bytes || 0),
              modified: String(obj.modified || ""),
              is_master_dossier: Boolean(obj.is_master_dossier),
            };
          }
          return null;
        })
        .filter((item): item is EnhancedReportFile => item !== null);
      setReports(normalizedReports);
    }
    if (snapR.ok && Array.isArray(snapR.data?.snapshots)) {
      const normalizedSnapshots = snapR.data.snapshots
        .map((item: unknown): SnapshotSummary | null => {
          if (typeof item === "string" && item.trim()) {
            const name = item.trim();
            return {
              filename: name,
              snapshot_id: name,
              target: "",
              phase: "",
              coverage_pct: 0,
              findings_count: 0,
              modified: "",
            };
          }
          if (item && typeof item === "object") {
            const obj = item as Record<string, unknown>;
            const filename = String(obj.filename || obj.snapshot_id || "").trim();
            const snapshotId = String(obj.snapshot_id || filename).trim();
            if (!filename && !snapshotId) return null;
            return {
              filename: filename || snapshotId,
              snapshot_id: snapshotId || filename,
              target: String(obj.target || ""),
              phase: String(obj.phase || ""),
              coverage_pct: Number(obj.coverage_pct || 0),
              findings_count: Number(obj.findings_count || 0),
              modified: String(obj.modified || ""),
            };
          }
          return null;
        })
        .filter((item): item is SnapshotSummary => item !== null);
      setSnapshots(normalizedSnapshots);
    }
    if (ledR.ok && ledR.data) setLedger(ledR.data);
  }, [apiJson]);

  useEffect(() => {
    void loadAll();
  }, [loadAll]);

  const counts = useMemo(() => {
    const c = { CONFIRMED: 0, SUSPECTED: 0, FALSE_POSITIVE: 0 };
    for (const r of results) {
      const k = (r.classification || "").toUpperCase();
      if (k in c) c[k as keyof typeof c] += 1;
    }
    return c;
  }, [results]);

  const filteredResults = useMemo(() => {
    if (classificationFilter === "ALL") return results;
    return results.filter((r) => (r.classification || "").toUpperCase() === classificationFilter);
  }, [results, classificationFilter]);

  const openReportDossier = async (filename: string) => {
    if (!filename) return;
    setExportError("");
    try {
      const res = await hunterFetch(`/api/enhanced/reports/${encodeURIComponent(filename)}`);
      if (!res.ok) {
        setExportError(`HTTP ${res.status}`);
        return;
      }
      const rawTxt = await res.text();
      let markdown = rawTxt;
      try {
        const parsed = JSON.parse(rawTxt) as { content?: unknown };
        if (parsed && typeof parsed === "object" && typeof parsed.content === "string") {
          markdown = parsed.content;
        }
      } catch {
        // Raw markdown body
      }
      setOpenedDossier({ title: filename, markdown });
    } catch (err) {
      setExportError(err instanceof Error ? err.message : t("common.error"));
    }
  };

  // Authenticated session export via hunterFetch + Blob download (preserves Bearer auth)
  const downloadSessionExport = async (sessionId: string, fmt: "hackerone" | "executive" | "md" | "json") => {
    const key = `${sessionId}:${fmt}`;
    setExportingKey(key);
    setExportError("");
    try {
      const res = await hunterFetch(`/api/report/${encodeURIComponent(sessionId)}/${fmt}`);
      if (!res.ok) {
        setExportError(`HTTP ${res.status}`);
        return;
      }
      const blob = await res.blob();
      const ext = fmt === "executive" ? "html" : fmt === "json" ? "json" : "md";
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `hunterai-${sessionId}-${fmt}.${ext}`;
      a.click();
      URL.revokeObjectURL(url);
    } catch (err) {
      setExportError(err instanceof Error ? err.message : t("common.error"));
    } finally {
      setExportingKey(null);
    }
  };

  const dossierHtml = useMemo(() => {
    if (!openedDossier) return "";
    return renderSafeMarkdown(openedDossier.markdown);
  }, [openedDossier]);

  return (
    <div className="space-y-5">
      {/* Triage Summary Row */}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
        <button
          type="button"
          onClick={() => setClassificationFilter((f) => (f === "CONFIRMED" ? "ALL" : "CONFIRMED"))}
          className={`sentinel-surface p-4 text-start transition-colors ${
            classificationFilter === "CONFIRMED" ? "border-sentinel-success" : "hover:border-border-strong"
          }`}
        >
          <div className="text-xs text-ink-muted">{t("findings.confirmedCount")}</div>
          <div className="text-2xl font-bold font-mono tabular-nums text-sentinel-success mt-1">
            {counts.CONFIRMED}
          </div>
        </button>

        <button
          type="button"
          onClick={() => setClassificationFilter((f) => (f === "SUSPECTED" ? "ALL" : "SUSPECTED"))}
          className={`sentinel-surface p-4 text-start transition-colors ${
            classificationFilter === "SUSPECTED" ? "border-sentinel-warning" : "hover:border-border-strong"
          }`}
        >
          <div className="text-xs text-ink-muted">{t("findings.suspectedCount")}</div>
          <div className="text-2xl font-bold font-mono tabular-nums text-sentinel-warning mt-1">
            {counts.SUSPECTED}
          </div>
        </button>

        <button
          type="button"
          onClick={() => setClassificationFilter((f) => (f === "FALSE_POSITIVE" ? "ALL" : "FALSE_POSITIVE"))}
          className={`sentinel-surface p-4 text-start transition-colors ${
            classificationFilter === "FALSE_POSITIVE" ? "border-sentinel-danger" : "hover:border-border-strong"
          }`}
        >
          <div className="text-xs text-ink-muted">{t("findings.falsePositiveCount")}</div>
          <div className="text-2xl font-bold font-mono tabular-nums text-ink-muted mt-1">
            {counts.FALSE_POSITIVE}
          </div>
        </button>
      </div>

      {/* Findings Table (Multi-Format Exporter) + Reports Explorer */}
      <div className="grid grid-cols-1 xl:grid-cols-12 gap-5">
        <div className="xl:col-span-6">
          <FindingsTable />
        </div>

        <section className="xl:col-span-6 sentinel-surface p-4 flex flex-col gap-3 h-[540px]">
          <div className="flex flex-wrap items-center justify-between gap-2 pb-3 border-b border-border-subtle">
            <div className="flex items-center gap-2">
              <ShieldCheck className="w-4 h-4 text-sentinel-success" />
              <h1 className="text-sm font-semibold text-ink-primary">{t("findings.explorerTitle")}</h1>
            </div>
            <button
              type="button"
              onClick={() => void loadAll()}
              className="h-8 px-2.5 rounded border border-border-subtle bg-elevated text-xs text-ink-primary flex items-center gap-1"
            >
              <RefreshCw className="w-3.5 h-3.5" />
              <span>{t("common.refresh")}</span>
            </button>
          </div>

          {exportError && (
            <div role="alert" className="px-3 py-1.5 rounded bg-sentinel-danger/10 border border-sentinel-danger/40 text-sentinel-danger text-xs">
              {exportError}
            </div>
          )}

          <div className="flex-1 overflow-y-auto space-y-3 pe-1">
            {filteredResults.length > 0 && (
              <div className="space-y-2">
                {filteredResults.map((item, idx) => (
                  <button
                    key={`${item.id || item.filename || item.title || "result"}-${idx}`}
                    type="button"
                    onClick={() =>
                      setOpenedDossier({
                        title: item.title,
                        markdown: `**Target:** \`${item.target}\`\n\n**Class:** \`${item.vulnerability_type}\`\n\n### Summary\n${item.summary}\n\n### Evidence\n\`\`\`\n${item.evidence}\n\`\`\`\n\n### Remediation\n${item.remediation}`,
                      })
                    }
                    className="w-full text-start p-3 rounded bg-elevated border border-border-subtle hover:border-border-strong space-y-1"
                  >
                    <div className="flex items-center justify-between gap-2 text-xs">
                      <span className="font-semibold text-ink-primary truncate">{item.title}</span>
                      <span className="font-mono text-[11px] px-2 py-0.5 rounded bg-inset border border-border-subtle text-sentinel-primary shrink-0">
                        {item.classification} · {item.severity}
                      </span>
                    </div>
                    <div className="font-mono text-[11px] text-ink-muted ltr-isolate truncate">
                      {item.target} · {item.platform}
                    </div>
                  </button>
                ))}
              </div>
            )}

            {/* Authenticated Session Reports */}
            {sessions.length > 0 && (
              <div className="pt-2 border-t border-border-subtle space-y-1.5">
                <div className="text-xs font-semibold text-ink-secondary">{t("findings.sessionExportsTitle")}</div>
                {sessions.slice(0, 10).map((s, idx) => (
                  <div key={`${s.id || "session"}-${idx}`} className="p-2.5 rounded bg-inset border border-border-subtle flex flex-wrap items-center justify-between gap-2 text-xs">
                    <span className="font-mono ltr-isolate truncate text-ink-primary">
                      {s.target || s.id} ({s.findings_count ?? 0})
                    </span>
                    <div className="flex items-center gap-1.5 font-mono">
                      {(["hackerone", "executive", "md", "json"] as const).map((fmt) => {
                        const busy = exportingKey === `${s.id}:${fmt}`;
                        return (
                          <button
                            key={fmt}
                            type="button"
                            disabled={busy}
                            onClick={() => void downloadSessionExport(s.id, fmt)}
                            className="px-2 py-0.5 rounded border border-border-subtle bg-elevated hover:border-sentinel-primary text-sentinel-primary inline-flex items-center gap-1 text-[11px] disabled:opacity-50"
                          >
                            {busy ? <Loader2 className="w-2.5 h-2.5 animate-spin" /> : <Download className="w-2.5 h-2.5" />}
                            <span>{fmt === "executive" ? "HTML" : fmt.toUpperCase()}</span>
                          </button>
                        );
                      })}
                    </div>
                  </div>
                ))}
              </div>
            )}

            {/* Markdown Master Dossiers */}
            {reports.length > 0 && (
              <div className="pt-2 border-t border-border-subtle space-y-1.5">
                <div className="text-xs font-semibold text-ink-secondary">{t("findings.generatedDossiersTitle")}</div>
                {reports.slice(0, 10).map((r, idx) => (
                  <div key={`${r.filename || "report"}-${idx}`} className="p-2 rounded bg-inset border border-border-subtle flex items-center justify-between gap-2 text-xs">
                    <span className="font-mono ltr-isolate truncate text-ink-secondary">{r.filename}</span>
                    <button
                      type="button"
                      onClick={() => void openReportDossier(r.filename)}
                      className="px-2 py-1 rounded border border-border-subtle bg-elevated hover:border-sentinel-primary text-sentinel-primary flex items-center gap-1 shrink-0"
                    >
                      <FileText className="w-3 h-3" />
                      <span>{t("common.details")}</span>
                    </button>
                  </div>
                ))}
              </div>
            )}

            {filteredResults.length === 0 && sessions.length === 0 && reports.length === 0 && (
              <div className="py-12 text-center text-xs text-ink-muted">{t("findings.emptyFindings")}</div>
            )}
          </div>
        </section>
      </div>

      {/* 7-State Evidence Court Workbench + Snapshots */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-5">
        <div className="lg:col-span-8">
          <EvidenceCourtDrawer embedded ledger={ledger} />
        </div>

        <section className="lg:col-span-4 sentinel-surface p-4 space-y-3">
          <div className="flex items-center gap-2 pb-2 border-b border-border-subtle">
            <Archive className="w-4 h-4 text-sentinel-ai" />
            <h2 className="text-sm font-semibold text-ink-primary">{t("findings.snapshotsTitle")}</h2>
          </div>

          {snapshots.length === 0 ? (
            <div className="py-8 text-center text-xs text-ink-muted">{t("common.noData")}</div>
          ) : (
            <div className="space-y-2 max-h-72 overflow-y-auto">
              {snapshots.map((sn, idx) => (
                <button
                  key={`${sn.filename || sn.snapshot_id || "snapshot"}-${idx}`}
                  type="button"
                  onClick={() => setInspectedSnapshot(sn)}
                  className="w-full text-start p-2.5 rounded bg-elevated border border-border-subtle hover:border-sentinel-primary text-xs space-y-1 transition-colors"
                >
                  <div className="flex items-center justify-between gap-2">
                    <span className="font-mono font-semibold text-ink-primary ltr-isolate truncate">
                      {sn.snapshot_id}
                    </span>
                    <span className="font-mono text-sentinel-success tabular-nums">
                      {Math.round(sn.coverage_pct || 0)}%
                    </span>
                  </div>
                  <div className="font-mono text-[11px] text-ink-muted ltr-isolate">
                    {sn.target} · {sn.phase} · {sn.findings_count} {t("runs.findingsTab")}
                  </div>
                </button>
              ))}
            </div>
          )}
        </section>
      </div>

      {/* Local Vulnerability Intelligence (NVD/OSV/KEV/CWE/ATT&CK) */}
      <VulnIntelPanel />

      {/* Copilot Ref Evidence Court Slide-Over */}
      {inspectedEvidenceId && (
        <EvidenceCourtDrawer
          ledger={ledger}
          selectedId={inspectedEvidenceId}
          onClose={() => setInspectedEvidenceId(null)}
        />
      )}

      {/* DOMPurify Sanitized Dossier Modal */}
      {openedDossier && (
        <div
          className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/60 backdrop-blur-[1px]"
          onClick={() => setOpenedDossier(null)}
        >
          <div
            ref={dossierTrapRef}
            role="dialog"
            aria-modal="true"
            aria-label={openedDossier.title}
            tabIndex={-1}
            onClick={(e) => e.stopPropagation()}
            className="w-full max-w-3xl max-h-[82vh] bg-surface border border-border-strong rounded-xl shadow-sentinelMd flex flex-col overflow-hidden"
          >
            <div className="px-5 py-3 border-b border-border-subtle flex items-center justify-between gap-3">
              <h3 className="text-sm font-semibold text-ink-primary truncate ltr-isolate">{openedDossier.title}</h3>
              <button
                type="button"
                onClick={() => setOpenedDossier(null)}
                aria-label={t("common.close")}
                className="min-h-[44px] min-w-[44px] sm:min-h-[32px] sm:min-w-[32px] rounded border border-border-subtle bg-elevated text-ink-primary flex items-center justify-center"
              >
                <X className="w-4 h-4" />
              </button>
            </div>
            <div className="flex-1 overflow-y-auto p-5">
              <div
                className="sentinel-prose"
                dangerouslySetInnerHTML={{ __html: dossierHtml }}
              />
            </div>
          </div>
        </div>
      )}

      {/* Snapshot Detail Modal */}
      {inspectedSnapshot && (
        <div
          className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/60 backdrop-blur-[1px]"
          onClick={() => setInspectedSnapshot(null)}
        >
          <div
            ref={snapshotTrapRef}
            role="dialog"
            aria-modal="true"
            aria-label={inspectedSnapshot.snapshot_id}
            tabIndex={-1}
            onClick={(e) => e.stopPropagation()}
            className="w-full max-w-lg bg-surface border border-border-strong rounded-xl shadow-sentinelMd overflow-hidden"
          >
            <div className="px-4 py-3 border-b border-border-subtle flex items-center justify-between gap-2">
              <h3 className="text-sm font-semibold text-ink-primary font-mono ltr-isolate truncate">
                {inspectedSnapshot.snapshot_id}
              </h3>
              <button
                type="button"
                onClick={() => setInspectedSnapshot(null)}
                aria-label={t("common.close")}
                className="h-8 w-8 rounded border border-border-subtle bg-elevated text-ink-primary flex items-center justify-center"
              >
                <X className="w-4 h-4" />
              </button>
            </div>
            <div className="p-4 grid grid-cols-2 gap-3 text-xs">
              <div className="p-2.5 rounded bg-inset border border-border-subtle">
                <div className="text-ink-muted">{t("common.target")}</div>
                <div className="font-mono text-ink-primary ltr-isolate mt-0.5">{inspectedSnapshot.target || "—"}</div>
              </div>
              <div className="p-2.5 rounded bg-inset border border-border-subtle">
                <div className="text-ink-muted">{t("runs.activePhase")}</div>
                <div className="font-mono text-ink-primary mt-0.5">{inspectedSnapshot.phase || "—"}</div>
              </div>
              <div className="p-2.5 rounded bg-inset border border-border-subtle">
                <div className="text-ink-muted">{t("runs.coverage")}</div>
                <div className="font-mono text-sentinel-success tabular-nums mt-0.5">
                  {Math.round(inspectedSnapshot.coverage_pct || 0)}%
                </div>
              </div>
              <div className="p-2.5 rounded bg-inset border border-border-subtle">
                <div className="text-ink-muted">{t("runs.findingsTab")}</div>
                <div className="font-mono text-ink-primary tabular-nums mt-0.5">{inspectedSnapshot.findings_count}</div>
              </div>
              <div className="col-span-2 p-2.5 rounded bg-inset border border-border-subtle">
                <div className="text-ink-muted">{t("findings.snapshotFileLabel")}</div>
                <div className="font-mono text-ink-secondary ltr-isolate mt-0.5 break-all">
                  {inspectedSnapshot.filename}
                  {inspectedSnapshot.modified ? ` · ${inspectedSnapshot.modified}` : ""}
                </div>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
