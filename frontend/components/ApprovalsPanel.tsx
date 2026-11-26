"use client";

import React, { useMemo, useState } from "react";
import { ShieldCheck, Check, XCircle, Clock, AlertTriangle } from "lucide-react";
import { usePlatform } from "@/lib/platform-context";
import { useI18n } from "@/lib/i18n";

function formatEpoch(epoch?: number | null): string {
  if (!epoch) return "—";
  return new Date(epoch * 1000).toLocaleTimeString("en-GB", { hour12: false });
}

export default function ApprovalsPanel() {
  const { approvals, hunterHubHealth, decideApproval } = usePlatform();
  const { t } = useI18n();

  const [tab, setTab] = useState<"pending" | "history">("pending");
  const [notesById, setNotesById] = useState<Record<string, string>>({});
  const [busyId, setBusyId] = useState<string | null>(null);
  const [errorMsg, setErrorMsg] = useState<string>("");

  const pendingApprovals = useMemo(
    () => approvals.filter((a) => a.status === "pending"),
    [approvals]
  );
  const recentApprovals = useMemo(
    () => approvals.filter((a) => a.status !== "pending").slice(0, 15),
    [approvals]
  );

  const visibleList = tab === "pending" ? pendingApprovals : recentApprovals;

  const handleDecision = async (approvalId: string, decision: "approved" | "rejected") => {
    setBusyId(approvalId);
    setErrorMsg("");
    const res = await decideApproval(approvalId, decision, notesById[approvalId] || "");
    if (!res.ok && res.error) {
      setErrorMsg(res.error);
    }
    setBusyId(null);
  };

  return (
    <section
      id="approvals-panel"
      aria-labelledby="approvals-heading"
      className="sentinel-surface p-4 flex flex-col gap-3"
    >
      <div className="flex flex-wrap items-center justify-between gap-2 pb-3 border-b border-border-subtle">
        <div className="flex items-center gap-2">
          <ShieldCheck className="w-4 h-4 text-sentinel-warning" />
          <h2 id="approvals-heading" className="text-sm font-semibold text-ink-primary">
            {t("approvals.title")}
          </h2>
          <span className="px-2 py-0.5 rounded-full text-xs font-mono tabular-nums bg-[var(--accent-warning-bg)] text-sentinel-warning border border-[var(--accent-warning)]/30">
            {pendingApprovals.length}
          </span>
        </div>

        <div role="tablist" className="flex items-center gap-1 bg-inset p-1 rounded-md border border-border-subtle">
          <button
            type="button"
            role="tab"
            aria-selected={tab === "pending"}
            onClick={() => setTab("pending")}
            className={`px-2.5 py-1 rounded text-xs font-medium transition-colors ${
              tab === "pending"
                ? "bg-elevated text-ink-primary border border-border-subtle"
                : "text-ink-muted hover:text-ink-primary"
            }`}
          >
            {t("approvals.pendingBadge")} ({pendingApprovals.length})
          </button>
          <button
            type="button"
            role="tab"
            aria-selected={tab === "history"}
            onClick={() => setTab("history")}
            className={`px-2.5 py-1 rounded text-xs font-medium transition-colors ${
              tab === "history"
                ? "bg-elevated text-ink-primary border border-border-subtle"
                : "text-ink-muted hover:text-ink-primary"
            }`}
          >
            {t("approvals.historyBadge")} ({recentApprovals.length})
          </button>
        </div>
      </div>

      {errorMsg && (
        <div
          role="alert"
          className="px-3 py-2 rounded-md border border-[var(--accent-danger)]/40 bg-[var(--accent-danger-bg)] text-sentinel-danger text-xs flex items-center gap-2"
        >
          <AlertTriangle className="w-4 h-4 shrink-0" />
          <span>{errorMsg}</span>
        </div>
      )}

      {hunterHubHealth.status === "offline" ? (
        <div className="py-6 text-center text-xs text-ink-muted">
          {t("approvals.offlineNotice")}
        </div>
      ) : visibleList.length === 0 ? (
        <div className="py-6 text-center text-xs text-ink-muted">
          {tab === "pending" ? t("approvals.emptyPending") : t("common.noData")}
        </div>
      ) : (
        <div className="space-y-2.5 max-h-80 overflow-y-auto pe-1">
          {visibleList.map((ap, idx) => {
            const isPending = ap.status === "pending";
            const isBusy = busyId === ap.approval_id;
            return (
              <div
                key={`${ap.approval_id || "ap"}-${idx}`}
                className="p-3 rounded-md bg-elevated border border-border-subtle space-y-2"
              >
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <div className="flex items-center gap-2 min-w-0">
                    <span className="text-[11px] font-mono px-2 py-0.5 rounded bg-[var(--accent-warning-bg)] text-sentinel-warning border border-[var(--accent-warning)]/30">
                      {ap.risk_tier}
                    </span>
                    <span className="text-xs font-semibold text-ink-primary font-mono">
                      {ap.action_type}
                    </span>
                    {ap.tool_name && (
                      <span className="text-xs font-mono text-sentinel-primary ltr-isolate">
                        {ap.tool_name}
                      </span>
                    )}
                  </div>
                  <div className="flex items-center gap-2 text-[11px] font-mono text-ink-muted">
                    <Clock className="w-3 h-3" />
                    <span className="tabular-nums">{formatEpoch(ap.created_at)}</span>
                    {!isPending && (
                      <span
                        className={`px-2 py-0.5 rounded border uppercase ${
                          ap.status === "approved"
                            ? "bg-[var(--accent-success-bg)] text-sentinel-success border-[var(--accent-success)]/30"
                            : "bg-[var(--accent-danger-bg)] text-sentinel-danger border-[var(--accent-danger)]/30"
                        }`}
                      >
                        {ap.status}
                      </span>
                    )}
                  </div>
                </div>

                {ap.target && (
                  <div className="text-xs font-mono text-ink-secondary ltr-isolate truncate">
                    {ap.target}
                  </div>
                )}

                {ap.rationale && (
                  <p className="text-xs text-ink-muted leading-relaxed">{ap.rationale}</p>
                )}

                {isPending && (
                  <div className="flex flex-wrap items-center gap-2 pt-1">
                    <input
                      type="text"
                      value={notesById[ap.approval_id] || ""}
                      onChange={(e) =>
                        setNotesById((prev) => ({
                          ...prev,
                          [ap.approval_id]: e.target.value,
                        }))
                      }
                      placeholder={t("approvals.notePlaceholder")}
                      aria-label={t("approvals.notePlaceholder")}
                      className="flex-1 min-w-[160px] h-8 px-2.5 rounded bg-inset border border-border-subtle text-xs text-ink-primary placeholder:text-ink-muted"
                    />
                    <button
                      type="button"
                      disabled={isBusy}
                      onClick={() => void handleDecision(ap.approval_id, "approved")}
                      className="h-8 px-3 rounded bg-[var(--accent-success-bg)] border border-[var(--accent-success)]/40 text-sentinel-success text-xs font-semibold flex items-center gap-1 hover:opacity-90 disabled:opacity-50"
                    >
                      <Check className="w-3.5 h-3.5" />
                      <span>{isBusy ? t("approvals.deciding") : t("approvals.approveBtn")}</span>
                    </button>
                    <button
                      type="button"
                      disabled={isBusy}
                      onClick={() => void handleDecision(ap.approval_id, "rejected")}
                      className="h-8 px-3 rounded bg-[var(--accent-danger-bg)] border border-[var(--accent-danger)]/40 text-sentinel-danger text-xs font-semibold flex items-center gap-1 hover:opacity-90 disabled:opacity-50"
                    >
                      <XCircle className="w-3.5 h-3.5" />
                      <span>{t("approvals.rejectBtn")}</span>
                    </button>
                  </div>
                )}
              </div>
            );
          })}
        </div>
      )}
    </section>
  );
}
