"use client";

import React, { useCallback, useDeferredValue, useEffect, useMemo, useState, useTransition } from "react";
import { DollarSign, Coins, RefreshCw, SlidersHorizontal, ChevronDown, ChevronUp } from "lucide-react";
import { BudgetBreakdownEntry, BudgetSummary } from "@/lib/api-types";
import { usePlatform } from "@/lib/platform-context";
import { useI18n } from "@/lib/i18n";

type BreakdownDimension = "by_provider" | "by_model" | "by_role" | "by_run";

interface NormalizedRow {
  key: string;
  usd: number;
  tokens: number;
  calls: number;
}

function normalizeBreakdown(
  raw?: Record<string, BudgetBreakdownEntry | number>
): NormalizedRow[] {
  if (!raw || typeof raw !== "object") return [];
  return Object.entries(raw)
    .map(([key, val]) => {
      if (typeof val === "number") {
        return { key, usd: val, tokens: 0, calls: 0 };
      }
      const tokens =
        typeof val.tokens === "number"
          ? val.tokens
          : Number(val.input_tokens || 0) + Number(val.output_tokens || 0);
      return {
        key,
        usd: Number(val.usd || 0),
        tokens,
        calls: Number(val.calls || 0),
      };
    })
    .sort((a, b) => b.usd - a.usd || b.tokens - a.tokens);
}

export default function TokenCostPanel({ runId }: { runId?: string | null }) {
  const { apiJson, hunterHubHealth } = usePlatform();
  const { t } = useI18n();

  const [budget, setBudget] = useState<BudgetSummary | null>(null);
  const [dimension, setDimension] = useState<BreakdownDimension>("by_provider");
  const [filterText, setFilterText] = useState<string>("");
  const deferredFilter = useDeferredValue(filterText);
  const [isPending, startTransition] = useTransition();

  const [showLimits, setShowLimits] = useState<boolean>(false);
  const [perRunUsd, setPerRunUsd] = useState<string>("");
  const [perSolverUsd, setPerSolverUsd] = useState<string>("");
  const [perDayUsd, setPerDayUsd] = useState<string>("");
  const [saveMsg, setSaveMsg] = useState<string>("");

  const loadBudget = useCallback(async () => {
    if (hunterHubHealth.status === "offline") return;
    const qs = runId ? `?run_id=${encodeURIComponent(runId)}` : "";
    const res = await apiJson<BudgetSummary>(`/api/budget${qs}`);
    if (res.ok && res.data) {
      setBudget(res.data);
      const limits = res.data.budget || res.data;
      setPerRunUsd(
        limits.per_run_usd !== undefined && limits.per_run_usd !== null
          ? String(limits.per_run_usd)
          : ""
      );
      setPerSolverUsd(
        limits.per_solver_usd !== undefined && limits.per_solver_usd !== null
          ? String(limits.per_solver_usd)
          : ""
      );
      setPerDayUsd(
        limits.per_day_usd !== undefined && limits.per_day_usd !== null
          ? String(limits.per_day_usd)
          : ""
      );
    }
  }, [apiJson, hunterHubHealth.status, runId]);

  useEffect(() => {
    void loadBudget();
  }, [loadBudget]);

  const rows = useMemo(() => {
    const raw = normalizeBreakdown(budget?.[dimension]);
    const q = deferredFilter.trim().toLowerCase();
    if (!q) return raw;
    return raw.filter((r) => r.key.toLowerCase().includes(q));
  }, [budget, dimension, deferredFilter]);

  const maxMetric = useMemo(() => {
    const maxUsd = Math.max(...rows.map((r) => r.usd), 0);
    if (maxUsd > 0) return { mode: "usd" as const, max: maxUsd };
    const maxTok = Math.max(...rows.map((r) => r.tokens), 1);
    return { mode: "tokens" as const, max: maxTok };
  }, [rows]);

  const saveLimits = async (e: React.FormEvent) => {
    e.preventDefault();
    setSaveMsg("");
    const toNum = (v: string): number | null => {
      const n = Number.parseFloat(v);
      return Number.isFinite(n) && n >= 0 ? n : null;
    };
    const res = await apiJson<BudgetSummary>("/api/budget", {
      method: "POST",
      body: {
        per_run_usd: toNum(perRunUsd),
        per_solver_usd: toNum(perSolverUsd),
        per_day_usd: toNum(perDayUsd),
      },
    });
    if (res.ok && res.data) {
      setBudget(res.data);
      setSaveMsg(t("budget.savedLimits"));
    } else {
      setSaveMsg(res.error || t("budget.saveError"));
    }
  };

  const todayUsd = Number(budget?.today_usd ?? budget?.spent?.today_usd ?? 0);
  const globalUsd = Number(budget?.global_usd ?? budget?.total_usd ?? budget?.spent?.total_usd ?? 0);
  const globalTokens = Number(budget?.global_tokens ?? 0);
  const totalCalls = Number(budget?.calls ?? 0);

  const dims: Array<{ id: BreakdownDimension; label: string }> = [
    { id: "by_provider", label: t("budget.byProvider") },
    { id: "by_model", label: t("budget.byModel") },
    { id: "by_role", label: t("budget.byRole") },
    { id: "by_run", label: t("budget.byRun") },
  ];

  return (
    <section
      data-testid="token-cost-panel"
      aria-labelledby="token-cost-heading"
      className="sentinel-surface p-4 flex flex-col gap-3"
    >
      <div className="flex flex-wrap items-center justify-between gap-2 pb-2 border-b border-border-subtle">
        <div className="flex items-center gap-2 min-w-0">
          <DollarSign className="w-4 h-4 text-sentinel-success shrink-0" />
          <h2 id="token-cost-heading" className="text-sm font-semibold text-ink-primary truncate">
            {t("budget.title")}
          </h2>
          {budget?.source && (
            <span className="px-1.5 py-0.5 rounded bg-elevated border border-border-subtle text-[10px] font-mono text-ink-muted ltr-isolate">
              {budget.source}
            </span>
          )}
        </div>

        <div className="flex items-center gap-1.5">
          <button
            type="button"
            onClick={() => void loadBudget()}
            aria-label={t("common.refresh")}
            className="h-8 w-8 rounded border border-border-subtle bg-elevated hover:border-border-strong text-ink-secondary hover:text-ink-primary flex items-center justify-center"
          >
            <RefreshCw className="w-3.5 h-3.5" />
          </button>
          <button
            type="button"
            aria-expanded={showLimits}
            onClick={() => setShowLimits((prev) => !prev)}
            className="h-8 px-2.5 rounded border border-border-subtle bg-elevated hover:border-border-strong text-xs text-ink-primary flex items-center gap-1"
          >
            <SlidersHorizontal className="w-3.5 h-3.5 text-sentinel-primary" />
            <span>{t("budget.limitsBtn")}</span>
            {showLimits ? <ChevronUp className="w-3 h-3" /> : <ChevronDown className="w-3 h-3" />}
          </button>
        </div>
      </div>

      {/* Headline Metrics */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 text-xs">
        <div className="p-2.5 rounded bg-inset border border-border-subtle">
          <div className="text-[11px] text-ink-muted">{t("budget.todaySpend")}</div>
          <div className="font-mono font-bold text-base tabular-nums text-sentinel-success ltr-isolate">
            ${todayUsd.toFixed(4)}
          </div>
        </div>
        <div className="p-2.5 rounded bg-inset border border-border-subtle">
          <div className="text-[11px] text-ink-muted">{t("budget.totalSpend")}</div>
          <div className="font-mono font-bold text-base tabular-nums text-ink-primary ltr-isolate">
            ${globalUsd.toFixed(4)}
          </div>
        </div>
        <div className="p-2.5 rounded bg-inset border border-border-subtle">
          <div className="text-[11px] text-ink-muted">{t("budget.totalTokens")}</div>
          <div className="font-mono font-bold text-base tabular-nums text-sentinel-primary ltr-isolate">
            {globalTokens.toLocaleString()}
          </div>
        </div>
        <div className="p-2.5 rounded bg-inset border border-border-subtle">
          <div className="text-[11px] text-ink-muted">{t("budget.totalCalls")}</div>
          <div className="font-mono font-bold text-base tabular-nums text-sentinel-ai ltr-isolate">
            {totalCalls.toLocaleString()}
          </div>
        </div>
      </div>

      {/* Dimension Selector + Filter */}
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div role="tablist" aria-label={t("budget.breakdownLabel")} className="flex flex-wrap gap-1 bg-inset p-1 rounded-md border border-border-subtle">
          {dims.map((d) => (
            <button
              key={d.id}
              type="button"
              role="tab"
              aria-selected={dimension === d.id}
              onClick={() => startTransition(() => setDimension(d.id))}
              className={`px-2 py-1 rounded text-[11px] font-medium transition-colors ${
                dimension === d.id
                  ? "bg-elevated text-sentinel-primary border border-border-subtle"
                  : "text-ink-muted hover:text-ink-primary"
              }`}
            >
              {d.label}
            </button>
          ))}
        </div>

        <input
          type="search"
          value={filterText}
          onChange={(e) => setFilterText(e.target.value)}
          placeholder={t("budget.filterPlaceholder")}
          aria-label={t("budget.filterPlaceholder")}
          className="h-8 px-2.5 rounded bg-inset border border-border-subtle text-xs text-ink-primary placeholder:text-ink-muted min-w-[140px]"
        />
      </div>

      {/* Responsive SVG Horizontal Bar Chart */}
      <div className={`space-y-2 ${isPending ? "opacity-70" : ""}`}>
        {rows.length === 0 ? (
          <div className="py-5 text-center text-xs text-ink-muted flex flex-col items-center gap-1.5">
            <Coins className="w-6 h-6 text-ink-muted opacity-50" />
            <span>{t("budget.emptyLedger")}</span>
          </div>
        ) : (
          <div className="p-3 rounded-md bg-inset border border-border-subtle space-y-2">
            <svg
              role="img"
              aria-label={t("budget.chartAriaLabel")}
              viewBox={`0 0 420 ${Math.max(44, rows.slice(0, 6).length * 30 + 8)}`}
              className="w-full h-auto overflow-visible"
            >
              {rows.slice(0, 6).map((row, idx) => {
                const metric = maxMetric.mode === "usd" ? row.usd : row.tokens;
                const widthPct = maxMetric.max > 0 ? Math.max(2, (metric / maxMetric.max) * 100) : 2;
                const barW = (widthPct / 100) * 210;
                const y = idx * 30 + 6;
                return (
                  <g key={row.key} transform={`translate(0, ${y})`}>
                    <text
                      x="0"
                      y="14"
                      className="fill-ink-secondary text-[10px] font-mono"
                    >
                      {row.key.length > 18 ? `${row.key.slice(0, 16)}…` : row.key}
                    </text>
                    <rect
                      x="128"
                      y="3"
                      width="210"
                      height="14"
                      rx="3"
                      className="fill-elevated"
                    />
                    <rect
                      x="128"
                      y="3"
                      width={barW}
                      height="14"
                      rx="3"
                      className={idx % 2 === 0 ? "fill-sentinel-primary" : "fill-sentinel-ai"}
                    />
                    <text
                      x="344"
                      y="14"
                      className="fill-ink-primary text-[10px] font-mono"
                    >
                      ${row.usd.toFixed(3)} · {row.tokens.toLocaleString()}t
                    </text>
                  </g>
                );
              })}
            </svg>
          </div>
        )}
      </div>

      {/* Collapsible Budget Ceilings Editor */}
      {showLimits && (
        <form onSubmit={saveLimits} className="pt-2 border-t border-border-subtle space-y-2.5 text-xs">
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-2">
            <div className="space-y-1">
              <label htmlFor="budget-run" className="text-ink-muted">
                {t("budget.perRunLimit")}
              </label>
              <input
                id="budget-run"
                type="number"
                step="0.5"
                min={0}
                value={perRunUsd}
                onChange={(e) => setPerRunUsd(e.target.value)}
                placeholder={t("budget.noCap")}
                className="w-full h-8 px-2.5 rounded bg-inset border border-border-subtle font-mono text-ink-primary ltr-isolate"
              />
            </div>

            <div className="space-y-1">
              <label htmlFor="budget-solver" className="text-ink-muted">
                {t("budget.perSolverLimit")}
              </label>
              <input
                id="budget-solver"
                type="number"
                step="0.25"
                min={0}
                value={perSolverUsd}
                onChange={(e) => setPerSolverUsd(e.target.value)}
                placeholder={t("budget.noCap")}
                className="w-full h-8 px-2.5 rounded bg-inset border border-border-subtle font-mono text-ink-primary ltr-isolate"
              />
            </div>

            <div className="space-y-1">
              <label htmlFor="budget-day" className="text-ink-muted">
                {t("budget.dailyLimit")}
              </label>
              <input
                id="budget-day"
                type="number"
                step="1"
                min={0}
                value={perDayUsd}
                onChange={(e) => setPerDayUsd(e.target.value)}
                placeholder={t("budget.noCap")}
                className="w-full h-8 px-2.5 rounded bg-inset border border-border-subtle font-mono text-ink-primary ltr-isolate"
              />
            </div>
          </div>

          <div className="flex items-center justify-between gap-2">
            <button
              type="submit"
              className="h-8 px-3 rounded bg-sentinel-primary text-sentinel-onAccent font-semibold hover:opacity-90"
            >
              {t("common.save")}
            </button>
            {saveMsg && <span className="font-mono text-sentinel-success">{saveMsg}</span>}
          </div>
        </form>
      )}
    </section>
  );
}
