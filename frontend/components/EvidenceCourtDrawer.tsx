"use client";

import React, { useMemo, useState } from "react";
import {
  Scale,
  X,
  Play,
  Loader2,
  CheckCircle2,
  AlertTriangle,
  ShieldAlert,
  HelpCircle,
  Ban,
  Clock,
} from "lucide-react";
import {
  COURT_VERDICT_STATES,
  CourtVerdictState,
  EvidenceLedgerResponse,
  EvidenceVerdict,
  normalizeCourtVerdict,
} from "@/lib/api-types";
import { usePlatform } from "@/lib/platform-context";
import { useI18n } from "@/lib/i18n";
import { useFocusTrap } from "@/hooks/use-focus-trap";

function verdictBadgeClass(state: CourtVerdictState): string {
  switch (state) {
    case "CONFIRMED":
      return "bg-sentinel-success/15 text-sentinel-success border-sentinel-success/40";
    case "CANDIDATE":
      return "bg-sentinel-warning/15 text-sentinel-warning border-sentinel-warning/40";
    case "REJECTED":
      return "bg-sentinel-danger/15 text-sentinel-danger border-sentinel-danger/40";
    case "INCONCLUSIVE":
      return "bg-sentinel-primary/15 text-sentinel-primary border-sentinel-primary/40";
    case "ERROR":
      return "bg-sentinel-danger/15 text-sentinel-danger border-sentinel-danger/40";
    case "UNAVAILABLE":
      return "bg-elevated text-ink-muted border-border-subtle";
    default:
      return "bg-inset text-ink-secondary border-border-subtle";
  }
}

function VerdictIcon({ state }: { state: CourtVerdictState }) {
  switch (state) {
    case "CONFIRMED":
      return <CheckCircle2 className="w-3.5 h-3.5 text-sentinel-success shrink-0" />;
    case "CANDIDATE":
      return <Clock className="w-3.5 h-3.5 text-sentinel-warning shrink-0" />;
    case "REJECTED":
      return <Ban className="w-3.5 h-3.5 text-sentinel-danger shrink-0" />;
    case "ERROR":
      return <AlertTriangle className="w-3.5 h-3.5 text-sentinel-danger shrink-0" />;
    case "INCONCLUSIVE":
      return <HelpCircle className="w-3.5 h-3.5 text-sentinel-primary shrink-0" />;
    default:
      return <ShieldAlert className="w-3.5 h-3.5 text-ink-muted shrink-0" />;
  }
}

interface EvidenceCourtDrawerProps {
  ledger: EvidenceLedgerResponse | null;
  selectedId?: string | null;
  onClose?: () => void;
  embedded?: boolean;
}

export default function EvidenceCourtDrawer({
  ledger,
  selectedId,
  onClose,
  embedded = false,
}: EvidenceCourtDrawerProps) {
  const { apiJson, selectedEngagement } = usePlatform();
  const { t } = useI18n();

  const [stateFilter, setStateFilter] = useState<"ALL" | CourtVerdictState>("ALL");
  const [activeVerdict, setActiveVerdict] = useState<EvidenceVerdict | null>(null);
  const [replayingId, setReplayingId] = useState<string | null>(null);
  const [replayOutput, setReplayOutput] = useState<Record<string, { ok: boolean; detail: string }>>(
    {}
  );

  const trapRef = useFocusTrap(!embedded && Boolean(selectedId), onClose);

  const verdicts = useMemo<EvidenceVerdict[]>(() => {
    const rawCourt = ledger?.recent?.court_verdict || [];
    const rawEvidence = ledger?.recent?.evidence || [];
    const combined: EvidenceVerdict[] = [];

    for (const row of rawCourt) {
      combined.push({
        court_id: String(row.court_id || ""),
        run_id: typeof row.run_id === "string" ? row.run_id : undefined,
        finding_id: typeof row.finding_id === "string" ? row.finding_id : undefined,
        evidence_id: String(row.court_id || row.finding_id || ""),
        title: String(row.title || row.finding_id || t("court.untitledVerdict")),
        endpoint: typeof row.endpoint === "string" ? row.endpoint : "",
        verdict: normalizeCourtVerdict(String(row.verdict || "")),
        reason_code: typeof row.reason_code === "string" ? row.reason_code : "",
        rationale: typeof row.rationale === "string" ? row.rationale : "",
        decided_at:
          typeof row.decided_at === "string" || typeof row.decided_at === "number"
            ? row.decided_at
            : null,
      });
    }

    for (const row of rawEvidence) {
      const id = String(row.evidence_id || row.id || "");
      if (id && combined.some((v) => v.evidence_id === id || v.finding_id === id)) continue;
      combined.push({
        evidence_id: id,
        run_id: typeof row.run_id === "string" ? row.run_id : undefined,
        title: String(row.title || row.evidence_type || row.source_tool || t("court.evidenceRecord")),
        endpoint: String(row.endpoint || row.target || ""),
        verdict: normalizeCourtVerdict(String(row.verification_status || row.status || "")),
        confidence: typeof row.confidence === "number" ? row.confidence : undefined,
        evidence: String(row.sanitized_content || row.content || ""),
        provenance:
          typeof row.provenance === "string" || (row.provenance && typeof row.provenance === "object")
            ? (row.provenance as Record<string, unknown> | string)
            : undefined,
      });
    }

    return combined;
  }, [ledger, t]);

  const countsByState = useMemo(() => {
    const map: Record<CourtVerdictState, number> = {
      UNVERIFIED: 0,
      CANDIDATE: 0,
      CONFIRMED: 0,
      REJECTED: 0,
      INCONCLUSIVE: 0,
      UNAVAILABLE: 0,
      ERROR: 0,
    };
    for (const v of verdicts) {
      map[v.verdict] += 1;
    }
    return map;
  }, [verdicts]);

  const filtered = useMemo(() => {
    if (stateFilter === "ALL") return verdicts;
    return verdicts.filter((v) => v.verdict === stateFilter);
  }, [verdicts, stateFilter]);

  const resolvedActive = useMemo(() => {
    if (activeVerdict) return activeVerdict;
    if (selectedId) {
      return (
        verdicts.find(
          (v) =>
            v.court_id === selectedId ||
            v.finding_id === selectedId ||
            v.evidence_id === selectedId
        ) || null
      );
    }
    return filtered[0] || null;
  }, [activeVerdict, selectedId, verdicts, filtered]);

  const handleReplay = async (item: EvidenceVerdict) => {
    const key = item.court_id || item.evidence_id || item.title;
    const targetUrl = item.endpoint || selectedEngagement?.target || "";
    setReplayingId(key);
    const res = await apiJson<{ ok?: boolean; result?: Record<string, unknown>; error?: string }>(
      "/api/probe/verify",
      {
        method: "POST",
        body: {
          url: targetUrl,
          target: targetUrl,
          finding_id: item.finding_id || item.court_id || undefined,
          vuln_class: item.vuln_class || undefined,
          in_scope: selectedEngagement?.in_scope,
          out_of_scope: selectedEngagement?.out_of_scope,
        },
      }
    );
    setReplayingId(null);
    if (res.ok && res.data) {
      setReplayOutput((prev) => ({
        ...prev,
        [key]: {
          ok: Boolean(res.data?.ok),
          detail: JSON.stringify(res.data?.result ?? res.data, null, 2),
        },
      }));
    } else {
      setReplayOutput((prev) => ({
        ...prev,
        [key]: { ok: false, detail: res.error || t("court.replayFailed") },
      }));
    }
  };

  const body = (
    <div className="space-y-3">
      {/* 7-State Filter Bar */}
      <div className="flex flex-wrap items-center gap-1.5" role="group" aria-label={t("court.stateFilters")}>
        <button
          type="button"
          onClick={() => setStateFilter("ALL")}
          aria-pressed={stateFilter === "ALL"}
          className={`px-2 py-1 rounded text-[11px] font-mono tabular-nums border ${
            stateFilter === "ALL"
              ? "border-sentinel-primary bg-sentinel-primary/15 text-sentinel-primary"
              : "border-border-subtle bg-elevated text-ink-muted hover:text-ink-primary"
          }`}
        >
          {t("common.all")} ({verdicts.length})
        </button>
        {COURT_VERDICT_STATES.map((st) => (
          <button
            key={st}
            type="button"
            onClick={() => setStateFilter(st)}
            aria-pressed={stateFilter === st}
            className={`px-2 py-1 rounded text-[11px] font-mono tabular-nums border ${
              stateFilter === st
                ? verdictBadgeClass(st)
                : "border-border-subtle bg-elevated text-ink-muted hover:text-ink-primary"
            }`}
          >
            {st} ({countsByState[st]})
          </button>
        ))}
      </div>

      {/* Workbench Split: Verdicts List + Causal Proof Viewer */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-3">
        <div className="lg:col-span-5 space-y-1.5 max-h-72 overflow-y-auto pe-1">
          {filtered.length === 0 ? (
            <div className="py-8 text-center text-xs text-ink-muted">{t("court.emptyVerdicts")}</div>
          ) : (
            filtered.map((item, idx) => {
              const key = item.court_id || item.evidence_id || `v-${idx}`;
              const isSelected = resolvedActive === item;
              return (
                <button
                  key={key}
                  type="button"
                  onClick={() => setActiveVerdict(item)}
                  className={`w-full text-start p-2.5 rounded-md border text-xs space-y-1 transition-colors ${
                    isSelected
                      ? "border-sentinel-primary bg-sentinel-primary/10"
                      : "border-border-subtle bg-elevated hover:border-border-strong"
                  }`}
                >
                  <div className="flex items-center justify-between gap-2">
                    <span className="flex items-center gap-1.5 font-semibold text-ink-primary min-w-0 truncate">
                      <VerdictIcon state={item.verdict} />
                      <span className="truncate">{item.title}</span>
                    </span>
                    <span
                      className={`px-1.5 py-0.5 rounded border text-[10px] font-mono shrink-0 ${verdictBadgeClass(item.verdict)}`}
                    >
                      {item.verdict}
                    </span>
                  </div>
                  {item.endpoint && (
                    <div className="font-mono text-[11px] text-ink-muted ltr-isolate truncate">
                      {item.endpoint}
                    </div>
                  )}
                </button>
              );
            })
          )}
        </div>

        <div className="lg:col-span-7 p-3 rounded-md bg-inset border border-border-subtle space-y-2.5 text-xs">
          {!resolvedActive ? (
            <div className="py-8 text-center text-ink-muted">{t("court.selectPrompt")}</div>
          ) : (
            <>
              <div className="flex flex-wrap items-center justify-between gap-2 pb-2 border-b border-border-subtle">
                <div className="min-w-0 space-y-0.5">
                  <div className="font-semibold text-ink-primary truncate">{resolvedActive.title}</div>
                  {resolvedActive.endpoint && (
                    <div className="font-mono text-[11px] text-sentinel-primary ltr-isolate break-all">
                      {resolvedActive.endpoint}
                    </div>
                  )}
                </div>
                <button
                  type="button"
                  disabled={
                    replayingId ===
                    (resolvedActive.court_id || resolvedActive.evidence_id || resolvedActive.title)
                  }
                  onClick={() => void handleReplay(resolvedActive)}
                  className="min-h-[34px] px-3 rounded bg-sentinel-primary text-sentinel-onAccent text-xs font-semibold flex items-center gap-1.5 hover:opacity-90 disabled:opacity-50 shrink-0"
                >
                  {replayingId ===
                  (resolvedActive.court_id || resolvedActive.evidence_id || resolvedActive.title) ? (
                    <Loader2 className="w-3.5 h-3.5 animate-spin" />
                  ) : (
                    <Play className="w-3.5 h-3.5" />
                  )}
                  <span>{t("court.replayBtn")}</span>
                </button>
              </div>

              <div className="grid grid-cols-2 gap-2 font-mono text-[11px]">
                <div className="p-2 rounded bg-elevated border border-border-subtle">
                  <div className="text-ink-muted">{t("court.verdictLabel")}</div>
                  <div className="text-ink-primary font-semibold">{resolvedActive.verdict}</div>
                </div>
                <div className="p-2 rounded bg-elevated border border-border-subtle">
                  <div className="text-ink-muted">{t("court.reasonCodeLabel")}</div>
                  <div className="text-ink-primary ltr-isolate truncate">
                    {resolvedActive.reason_code || "—"}
                  </div>
                </div>
              </div>

              {resolvedActive.rationale && (
                <div className="space-y-1">
                  <div className="text-[11px] font-semibold text-ink-muted">
                    {t("court.rationaleLabel")}
                  </div>
                  <p className="text-ink-secondary leading-relaxed">{resolvedActive.rationale}</p>
                </div>
              )}

              {resolvedActive.evidence && (
                <div className="space-y-1">
                  <div className="text-[11px] font-semibold text-ink-muted">
                    {t("court.proofLabel")}
                  </div>
                  <pre
                    dir="ltr"
                    className="ltr-isolate p-2.5 rounded bg-surface border border-border-subtle font-mono text-[11px] text-ink-secondary max-h-32 overflow-auto whitespace-pre-wrap break-all"
                  >
                    {resolvedActive.evidence}
                  </pre>
                </div>
              )}

              {(() => {
                const rk =
                  resolvedActive.court_id || resolvedActive.evidence_id || resolvedActive.title;
                const ro = replayOutput[rk];
                if (!ro) return null;
                return (
                  <div
                    role="status"
                    className={`p-2.5 rounded border text-[11px] font-mono space-y-1 ${
                      ro.ok
                        ? "border-sentinel-success/40 bg-sentinel-success/10 text-sentinel-success"
                        : "border-sentinel-warning/40 bg-sentinel-warning/10 text-sentinel-warning"
                    }`}
                  >
                    <div className="font-semibold">{t("court.replayResultTitle")}</div>
                    <pre dir="ltr" className="ltr-isolate whitespace-pre-wrap break-all max-h-28 overflow-auto">
                      {ro.detail}
                    </pre>
                  </div>
                );
              })()}
            </>
          )}
        </div>
      </div>
    </div>
  );

  if (embedded) {
    return (
      <section
        data-testid="evidence-court-workbench"
        aria-labelledby="evidence-court-heading"
        className="sentinel-surface p-4 space-y-3"
      >
        <div className="flex items-center justify-between gap-2 pb-2 border-b border-border-subtle">
          <div className="flex items-center gap-2">
            <Scale className="w-4 h-4 text-sentinel-primary" />
            <h2 id="evidence-court-heading" className="text-sm font-semibold text-ink-primary">
              {t("court.title")}
            </h2>
          </div>
          <span className="text-xs font-mono text-ink-muted tabular-nums">
            {verdicts.length} {t("court.recordsSuffix")}
          </span>
        </div>
        {body}
      </section>
    );
  }

  if (!selectedId) return null;

  return (
    <div
      className="fixed inset-0 z-50 flex justify-end bg-black/55 backdrop-blur-[1px]"
      onClick={onClose}
    >
      <div
        ref={trapRef}
        role="dialog"
        aria-modal="true"
        aria-labelledby="evidence-court-drawer-title"
        tabIndex={-1}
        onClick={(e) => e.stopPropagation()}
        className="w-full max-w-3xl h-full bg-surface border-s border-border-strong shadow-sentinelMd flex flex-col overflow-hidden"
      >
        <div className="px-5 py-4 border-b border-border-subtle flex items-center justify-between gap-3">
          <div className="flex items-center gap-2">
            <Scale className="w-4 h-4 text-sentinel-primary" />
            <h2 id="evidence-court-drawer-title" className="text-sm font-semibold text-ink-primary">
              {t("court.title")}
            </h2>
          </div>
          <button
            type="button"
            onClick={onClose}
            aria-label={t("common.close")}
            className="min-h-[44px] min-w-[44px] lg:min-h-0 lg:min-w-0 lg:h-8 lg:w-8 rounded border border-border-subtle bg-elevated text-ink-primary flex items-center justify-center"
          >
            <X className="w-4 h-4" />
          </button>
        </div>
        <div className="flex-1 overflow-y-auto p-5">{body}</div>
      </div>
    </div>
  );
}
