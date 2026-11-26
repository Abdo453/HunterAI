"use client";

import React, { useCallback, useEffect, useState } from "react";
import {
  Rocket,
  Play,
  Pause,
  Square,
  Eye,
  X,
  DollarSign,
  Loader2,
  AlertCircle,
  CheckCircle2,
  Activity,
} from "lucide-react";
import StatsCards from "@/components/StatsCards";
import ApprovalsPanel from "@/components/ApprovalsPanel";
import LiveConsole from "@/components/LiveConsole";
import {
  MissionLaunchInput,
  RunRecord,
  usePlatform,
  validateScanTarget,
} from "@/lib/platform-context";
import { useI18n } from "@/lib/i18n";

interface BudgetSnapshot {
  budget?: {
    per_run_usd?: number | null;
    per_solver_usd?: number | null;
    per_day_usd?: number | null;
  };
  spent?: {
    today_usd?: number;
    total_usd?: number;
  };
  per_run_usd?: number | null;
  per_solver_usd?: number | null;
  per_day_usd?: number | null;
  today_usd?: number;
  total_usd?: number;
}

interface RunDetailsData {
  events: Array<{ event_id?: string; event_type?: string; timestamp?: number | string; payload?: Record<string, unknown> }>;
  evidence: Array<{ evidence_id?: string; source_tool?: string; evidence_type?: string; confidence?: number; sanitized_content?: string }>;
  findings: Array<{ evidence_id?: string; title?: string; affected_asset?: string; confidence?: number; verification_status?: string; evidence?: string }>;
}

const RUN_KINDS: Array<{ id: MissionLaunchInput["kind"]; label: string }> = [
  { id: "omni", label: "OmniHunter (Full Loop)" },
  { id: "pipeline", label: "Recon Pipeline" },
  { id: "mission", label: "Autonomous Mission" },
  { id: "engine", label: "CLI Engine Worker" },
  { id: "go_core", label: "Go Core Scanner" },
];

function statusPillClass(status: string): string {
  const norm = status.toLowerCase();
  if (norm === "running") {
    return "bg-[var(--accent-primary-bg)] text-sentinel-primary border-[var(--accent-primary)]/35";
  }
  if (norm === "paused" || norm === "pending") {
    return "bg-[var(--accent-warning-bg)] text-sentinel-warning border-[var(--accent-warning)]/35";
  }
  if (norm === "completed") {
    return "bg-[var(--accent-success-bg)] text-sentinel-success border-[var(--accent-success)]/35";
  }
  return "bg-[var(--accent-danger-bg)] text-sentinel-danger border-[var(--accent-danger)]/35";
}

export default function OverviewPage() {
  const {
    selectedEngagement,
    targetDomain,
    runs,
    isScanning,
    launchMission,
    controlRun,
    apiJson,
    hunterHubHealth,
  } = usePlatform();
  const { t } = useI18n();

  const [kind, setKind] = useState<MissionLaunchInput["kind"]>("omni");
  const [target, setTarget] = useState<string>(targetDomain || "");
  const [mode, setMode] = useState<string>("full");
  const [engineName, setEngineName] = useState<string>("claude");
  const [prompt, setPrompt] = useState<string>("");
  const [cycles, setCycles] = useState<number>(10);
  const [coverage, setCoverage] = useState<number>(0.85);
  const [proxyUrl, setProxyUrl] = useState<string>("");
  const [launchError, setLaunchError] = useState<string>("");
  const [launchFeedback, setLaunchFeedback] = useState<string>("");

  const [inspectedRun, setInspectedRun] = useState<RunRecord | null>(null);
  const [runTab, setRunTab] = useState<"events" | "evidence" | "findings">("events");
  const [runDetails, setRunDetails] = useState<RunDetailsData>({ events: [], evidence: [], findings: [] });
  const [runLoading, setRunLoading] = useState<boolean>(false);

  const [budget, setBudget] = useState<BudgetSnapshot | null>(null);
  const [perRunUsd, setPerRunUsd] = useState<string>("");
  const [perSolverUsd, setPerSolverUsd] = useState<string>("");
  const [perDayUsd, setPerDayUsd] = useState<string>("");
  const [budgetMsg, setBudgetMsg] = useState<string>("");

  useEffect(() => {
    if (selectedEngagement?.target) {
      setTarget(selectedEngagement.target);
    }
  }, [selectedEngagement]);

  const loadBudget = useCallback(async () => {
    if (hunterHubHealth.status === "offline") return;
    const res = await apiJson<BudgetSnapshot>("/api/budget");
    if (res.ok && res.data) {
      setBudget(res.data);
      const b = res.data.budget || res.data;
      setPerRunUsd(b.per_run_usd !== undefined && b.per_run_usd !== null ? String(b.per_run_usd) : "");
      setPerSolverUsd(b.per_solver_usd !== undefined && b.per_solver_usd !== null ? String(b.per_solver_usd) : "");
      setPerDayUsd(b.per_day_usd !== undefined && b.per_day_usd !== null ? String(b.per_day_usd) : "");
    }
  }, [apiJson, hunterHubHealth.status]);

  useEffect(() => {
    void loadBudget();
  }, [loadBudget]);

  const handleLaunch = async (e: React.FormEvent) => {
    e.preventDefault();
    setLaunchError("");
    setLaunchFeedback("");

    if (kind !== "engine" || target.trim()) {
      const check = validateScanTarget(target, selectedEngagement);
      if (!check.valid) {
        setLaunchError(t(
          check.reason === "empty"
            ? "nav.scopeInvalidEmpty"
            : check.reason === "blocked_metadata"
              ? "nav.scopeInvalidMetadata"
              : check.reason === "out_of_scope"
                ? "nav.scopeOutOfScope"
                : check.reason === "not_in_scope"
                  ? "nav.scopeNotInScope"
                  : "nav.scopeFormatHint"
        ));
        return;
      }
    }

    const res = await launchMission({
      kind,
      target: target.trim(),
      mode,
      engine: engineName,
      prompt,
      max_cycles: cycles,
      coverage,
      proxy: proxyUrl.trim() || null,
    });
    if (!res.ok) {
      setLaunchError(res.error || "Launch failed");
      return;
    }
    setLaunchFeedback(res.run?.run_id ? `Started ${res.run.run_id}` : "Dispatched");
  };

  const inspectRunDetails = async (run: RunRecord) => {
    setInspectedRun(run);
    setRunTab("events");
    setRunLoading(true);
    const [evRes, eviRes, fRes] = await Promise.all([
      apiJson<{ events?: RunDetailsData["events"] }>(`/api/runs/${encodeURIComponent(run.run_id)}/events`),
      apiJson<{ evidence?: RunDetailsData["evidence"] }>(`/api/runs/${encodeURIComponent(run.run_id)}/evidence`),
      apiJson<{ findings?: RunDetailsData["findings"] }>(`/api/runs/${encodeURIComponent(run.run_id)}/findings`),
    ]);
    setRunDetails({
      events: evRes.ok && Array.isArray(evRes.data?.events) ? evRes.data.events : [],
      evidence: eviRes.ok && Array.isArray(eviRes.data?.evidence) ? eviRes.data.evidence : [],
      findings: fRes.ok && Array.isArray(fRes.data?.findings) ? fRes.data.findings : [],
    });
    setRunLoading(false);
  };

  const saveBudget = async (e: React.FormEvent) => {
    e.preventDefault();
    setBudgetMsg("");
    const toNum = (v: string): number | null => {
      const n = Number.parseFloat(v);
      return Number.isFinite(n) && n >= 0 ? n : null;
    };
    const res = await apiJson<BudgetSnapshot>("/api/budget", {
      method: "POST",
      body: {
        per_run_usd: toNum(perRunUsd),
        per_solver_usd: toNum(perSolverUsd),
        per_day_usd: toNum(perDayUsd),
      },
    });
    if (res.ok && res.data) {
      setBudget(res.data);
      setBudgetMsg(t("common.save"));
    } else {
      setBudgetMsg(res.error || "Failed");
    }
  };

  return (
    <div className="space-y-5">
      <StatsCards />

      {/* Unified Mission Launcher */}
      <section aria-labelledby="mission-launcher-heading" className="sentinel-surface p-4 space-y-3">
        <div className="flex flex-wrap items-center justify-between gap-2 pb-3 border-b border-border-subtle">
          <div className="flex items-center gap-2">
            <Rocket className="w-4 h-4 text-sentinel-primary" />
            <h2 id="mission-launcher-heading" className="text-sm font-semibold text-ink-primary">
              {t("runs.title")}
            </h2>
          </div>

          <div className="flex flex-wrap gap-1 bg-inset p-1 rounded-md border border-border-subtle">
            {RUN_KINDS.map((item) => (
              <button
                key={item.id}
                type="button"
                onClick={() => setKind(item.id)}
                className={`px-2.5 py-1 rounded text-xs font-mono transition-colors ${
                  kind === item.id
                    ? "bg-elevated text-sentinel-primary border border-border-subtle"
                    : "text-ink-muted hover:text-ink-primary"
                }`}
              >
                {item.label}
              </button>
            ))}
          </div>
        </div>

        <form onSubmit={handleLaunch} className="grid grid-cols-1 md:grid-cols-12 gap-3 items-end">
          <div className="md:col-span-4 space-y-1">
            <label htmlFor="overview-target" className="text-xs text-ink-muted">
              {t("common.target")}
            </label>
            <input
              id="overview-target"
              type="text"
              dir="ltr"
              value={target}
              onChange={(e) => setTarget(e.target.value)}
              placeholder={t("runs.targetPlaceholder")}
              className="ltr-isolate w-full h-9 px-3 rounded-md bg-inset border border-border-subtle text-xs font-mono text-ink-primary"
            />
          </div>

          <div className="md:col-span-2 space-y-1">
            <label htmlFor="overview-mode" className="text-xs text-ink-muted">
              {t("copilot.modeLabel")}
            </label>
            <select
              id="overview-mode"
              value={mode}
              onChange={(e) => setMode(e.target.value)}
              className="w-full h-9 px-2.5 rounded-md bg-inset border border-border-subtle text-xs text-ink-primary"
            >
              <option value="full">full</option>
              <option value="recon">recon</option>
              <option value="web">web</option>
              <option value="passive">passive</option>
            </select>
          </div>

          <div className="md:col-span-2 space-y-1">
            <label htmlFor="overview-cycles" className="text-xs text-ink-muted">
              {t("runs.cyclesLabel")}
            </label>
            <input
              id="overview-cycles"
              type="number"
              min={1}
              max={50}
              value={cycles}
              onChange={(e) => setCycles(Number(e.target.value) || 10)}
              className="w-full h-9 px-2.5 rounded-md bg-inset border border-border-subtle text-xs font-mono tabular-nums text-ink-primary ltr-isolate"
            />
          </div>

          <div className="md:col-span-2 space-y-1">
            <label htmlFor="overview-proxy" className="text-xs text-ink-muted">
              Proxy (Optional)
            </label>
            <input
              id="overview-proxy"
              type="text"
              dir="ltr"
              value={proxyUrl}
              onChange={(e) => setProxyUrl(e.target.value)}
              placeholder="http://127.0.0.1:8080"
              className="ltr-isolate w-full h-9 px-2.5 rounded-md bg-inset border border-border-subtle text-xs font-mono text-ink-primary"
            />
          </div>

          <div className="md:col-span-2">
            <button
              type="submit"
              disabled={isScanning}
              className="w-full h-9 px-3 rounded-md bg-sentinel-primary text-sentinel-onAccent text-xs font-semibold flex items-center justify-center gap-1.5 hover:opacity-90 disabled:opacity-50"
            >
              {isScanning ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Play className="w-3.5 h-3.5" />}
              <span>{t("runs.launchMission")}</span>
            </button>
          </div>

          {kind === "engine" && (
            <>
              <div className="md:col-span-3 space-y-1">
                <label htmlFor="overview-engine" className="text-xs text-ink-muted">
                  CLI Engine
                </label>
                <select
                  id="overview-engine"
                  value={engineName}
                  onChange={(e) => setEngineName(e.target.value)}
                  className="w-full h-9 px-2.5 rounded-md bg-inset border border-border-subtle text-xs font-mono text-ink-primary"
                >
                  <option value="claude">claude</option>
                  <option value="codex">codex</option>
                  <option value="opencode">opencode</option>
                  <option value="gemini">gemini</option>
                </select>
              </div>
              <div className="md:col-span-7 space-y-1">
                <label htmlFor="overview-prompt" className="text-xs text-ink-muted">
                  Task Prompt
                </label>
                <input
                  id="overview-prompt"
                  type="text"
                  value={prompt}
                  onChange={(e) => setPrompt(e.target.value)}
                  placeholder="Instruction for autonomous CLI engine..."
                  className="w-full h-9 px-3 rounded-md bg-inset border border-border-subtle text-xs text-ink-primary"
                />
              </div>
              <div className="md:col-span-2 space-y-1">
                <label htmlFor="overview-cov" className="text-xs text-ink-muted">
                  Coverage Target
                </label>
                <input
                  id="overview-cov"
                  type="number"
                  step="0.05"
                  min={0.1}
                  max={1}
                  value={coverage}
                  onChange={(e) => setCoverage(Number(e.target.value) || 0.85)}
                  className="w-full h-9 px-2.5 rounded-md bg-inset border border-border-subtle text-xs font-mono text-ink-primary ltr-isolate"
                />
              </div>
            </>
          )}
        </form>

        {launchError && (
          <div role="alert" className="px-3 py-2 rounded bg-[var(--accent-danger-bg)] border border-[var(--accent-danger)]/40 text-sentinel-danger text-xs flex items-center gap-2">
            <AlertCircle className="w-4 h-4 shrink-0" />
            <span>{launchError}</span>
          </div>
        )}
        {launchFeedback && (
          <div role="status" className="px-3 py-2 rounded bg-[var(--accent-success-bg)] border border-[var(--accent-success)]/40 text-sentinel-success text-xs flex items-center gap-2">
            <CheckCircle2 className="w-4 h-4 shrink-0" />
            <span className="font-mono">{launchFeedback}</span>
          </div>
        )}
      </section>

      {/* Active Runs + Budget Guard */}
      <div className="grid grid-cols-1 xl:grid-cols-12 gap-5">
        <section className="xl:col-span-8 sentinel-surface p-4 flex flex-col gap-3">
          <div className="flex items-center justify-between gap-2 pb-2 border-b border-border-subtle">
            <div className="flex items-center gap-2">
              <Activity className="w-4 h-4 text-sentinel-primary" />
              <h3 className="text-sm font-semibold text-ink-primary">Managed Runs</h3>
              <span className="text-xs font-mono tabular-nums px-2 py-0.5 rounded bg-elevated border border-border-subtle text-ink-secondary">
                {runs.length}
              </span>
            </div>
          </div>

          {runs.length === 0 ? (
            <div className="py-8 text-center text-xs text-ink-muted">{t("runs.emptyRuns")}</div>
          ) : (
            <div className="overflow-x-auto border border-border-subtle rounded-md bg-inset">
              <table className="w-full text-xs border-collapse">
                <thead className="bg-elevated border-b border-border-subtle text-ink-muted">
                  <tr>
                    <th className="py-2 px-3 text-start font-semibold">Run ID</th>
                    <th className="py-2 px-3 text-start font-semibold">Kind</th>
                    <th className="py-2 px-3 text-start font-semibold">{t("common.target")}</th>
                    <th className="py-2 px-3 text-start font-semibold">{t("runs.activePhase")}</th>
                    <th className="py-2 px-3 text-start font-semibold">{t("common.status")}</th>
                    <th className="py-2 px-3 text-start font-semibold">{t("common.actions")}</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-border-subtle">
                  {runs.slice(0, 20).map((run, idx) => {
                    const st = (run.status || "").toLowerCase();
                    return (
                      <tr key={`${run.run_id || "run"}-${idx}`} className="hover:bg-elevated/60">
                        <td className="py-2 px-3 font-mono text-ink-primary ltr-isolate whitespace-nowrap">
                          {run.run_id}
                        </td>
                        <td className="py-2 px-3 font-mono text-sentinel-primary uppercase whitespace-nowrap">
                          {run.kind}
                        </td>
                        <td className="py-2 px-3 font-mono text-ink-secondary ltr-isolate max-w-[180px] truncate">
                          {run.target || "—"}
                        </td>
                        <td className="py-2 px-3 font-mono text-ink-muted tabular-nums whitespace-nowrap">
                          {run.current_phase || "—"}
                          {typeof run.progress === "number" ? ` (${Math.round(run.progress)}%)` : ""}
                        </td>
                        <td className="py-2 px-3 whitespace-nowrap">
                          <span className={`text-[11px] font-mono px-2 py-0.5 rounded border uppercase ${statusPillClass(st)}`}>
                            {st}
                          </span>
                        </td>
                        <td className="py-2 px-3 whitespace-nowrap">
                          <div className="flex items-center gap-1">
                            {st === "running" && (
                              <button
                                type="button"
                                onClick={() => void controlRun(run.run_id, "pause")}
                                title={t("runs.pauseRun")}
                                className="h-7 px-2 rounded border border-border-subtle bg-elevated hover:border-border-strong text-ink-primary"
                              >
                                <Pause className="w-3.5 h-3.5 text-sentinel-warning" />
                              </button>
                            )}
                            {st === "paused" && (
                              <button
                                type="button"
                                onClick={() => void controlRun(run.run_id, "resume")}
                                title={t("runs.resumeRun")}
                                className="h-7 px-2 rounded border border-border-subtle bg-elevated hover:border-border-strong text-ink-primary"
                              >
                                <Play className="w-3.5 h-3.5 text-sentinel-success" />
                              </button>
                            )}
                            {["running", "paused", "pending"].includes(st) && (
                              <button
                                type="button"
                                onClick={() => void controlRun(run.run_id, "stop")}
                                title={t("runs.stopRun")}
                                className="h-7 px-2 rounded border border-border-subtle bg-elevated hover:border-border-strong text-ink-primary"
                              >
                                <Square className="w-3.5 h-3.5 text-sentinel-danger" />
                              </button>
                            )}
                            <button
                              type="button"
                              onClick={() => void inspectRunDetails(run)}
                              title={t("common.details")}
                              className="h-7 px-2 rounded border border-border-subtle bg-elevated hover:border-border-strong text-ink-secondary hover:text-ink-primary flex items-center gap-1"
                            >
                              <Eye className="w-3.5 h-3.5" />
                              <span>{t("common.details")}</span>
                            </button>
                          </div>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}
        </section>

        {/* Budget Guard */}
        <section className="xl:col-span-4 sentinel-surface p-4 flex flex-col gap-3">
          <div className="flex items-center justify-between pb-2 border-b border-border-subtle">
            <div className="flex items-center gap-2">
              <DollarSign className="w-4 h-4 text-sentinel-success" />
              <h3 className="text-sm font-semibold text-ink-primary">Cost & Budget Guard</h3>
            </div>
            <span className="text-xs font-mono tabular-nums text-ink-muted ltr-isolate">
              Today: ${(budget?.spent?.today_usd ?? budget?.today_usd ?? 0).toFixed(2)}
            </span>
          </div>

          <form onSubmit={saveBudget} className="space-y-2.5 text-xs">
            <div className="space-y-1">
              <label htmlFor="budget-run" className="text-ink-muted">
                Per Run Limit (USD)
              </label>
              <input
                id="budget-run"
                type="number"
                step="0.5"
                min={0}
                value={perRunUsd}
                onChange={(e) => setPerRunUsd(e.target.value)}
                placeholder="No cap"
                className="w-full h-8 px-2.5 rounded bg-inset border border-border-subtle font-mono text-ink-primary ltr-isolate"
              />
            </div>

            <div className="space-y-1">
              <label htmlFor="budget-solver" className="text-ink-muted">
                Per Solver Limit (USD)
              </label>
              <input
                id="budget-solver"
                type="number"
                step="0.25"
                min={0}
                value={perSolverUsd}
                onChange={(e) => setPerSolverUsd(e.target.value)}
                placeholder="No cap"
                className="w-full h-8 px-2.5 rounded bg-inset border border-border-subtle font-mono text-ink-primary ltr-isolate"
              />
            </div>

            <div className="space-y-1">
              <label htmlFor="budget-day" className="text-ink-muted">
                Daily Limit (USD)
              </label>
              <input
                id="budget-day"
                type="number"
                step="1"
                min={0}
                value={perDayUsd}
                onChange={(e) => setPerDayUsd(e.target.value)}
                placeholder="No cap"
                className="w-full h-8 px-2.5 rounded bg-inset border border-border-subtle font-mono text-ink-primary ltr-isolate"
              />
            </div>

            <div className="flex items-center justify-between gap-2 pt-1">
              <button
                type="submit"
                className="h-8 px-3 rounded bg-sentinel-primary text-sentinel-onAccent font-semibold hover:opacity-90"
              >
                {t("common.save")}
              </button>
              {budgetMsg && <span className="font-mono text-sentinel-success">{budgetMsg}</span>}
            </div>
          </form>
        </section>
      </div>

      {/* Approvals & Live Console */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-5">
        <div className="lg:col-span-5">
          <ApprovalsPanel />
        </div>
        <div className="lg:col-span-7">
          <LiveConsole />
        </div>
      </div>

      {/* Run Inspector Slide-Over Drawer */}
      {inspectedRun && (
        <div
          className="fixed inset-0 z-50 flex justify-end bg-black/55 backdrop-blur-[1px]"
          onClick={() => setInspectedRun(null)}
        >
          <div
            role="dialog"
            aria-modal="true"
            aria-label={`Run ${inspectedRun.run_id}`}
            onClick={(e) => e.stopPropagation()}
            className="w-full max-w-2xl h-full bg-surface border-s border-border-subtle shadow-sentinelMd flex flex-col overflow-hidden"
          >
            <div className="px-5 py-4 border-b border-border-subtle flex items-center justify-between gap-3">
              <div className="min-w-0">
                <div className="text-xs font-mono text-sentinel-primary ltr-isolate">
                  {inspectedRun.kind} · {inspectedRun.run_id}
                </div>
                <h3 className="text-sm font-semibold text-ink-primary truncate ltr-isolate">
                  {inspectedRun.target || inspectedRun.run_id}
                </h3>
              </div>
              <button
                type="button"
                onClick={() => setInspectedRun(null)}
                aria-label={t("common.close")}
                className="h-9 w-9 rounded border border-border-subtle bg-elevated text-ink-primary flex items-center justify-center"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <div className="px-5 py-2.5 border-b border-border-subtle flex items-center gap-2 bg-elevated/60">
              {(["events", "evidence", "findings"] as const).map((tabKey) => (
                <button
                  key={tabKey}
                  type="button"
                  onClick={() => setRunTab(tabKey)}
                  className={`px-3 py-1 rounded text-xs font-medium ${
                    runTab === tabKey
                      ? "bg-[var(--accent-primary-bg)] text-sentinel-primary border border-[var(--accent-primary)]/40"
                      : "text-ink-muted hover:text-ink-primary"
                  }`}
                >
                  {tabKey === "events"
                    ? `${t("runs.eventsTab")} (${runDetails.events.length})`
                    : tabKey === "evidence"
                      ? `${t("runs.evidenceTab")} (${runDetails.evidence.length})`
                      : `${t("runs.findingsTab")} (${runDetails.findings.length})`}
                </button>
              ))}
            </div>

            <div className="flex-1 overflow-y-auto p-5 space-y-2.5 text-xs">
              {runLoading ? (
                <div className="py-10 flex items-center justify-center gap-2 text-ink-muted">
                  <Loader2 className="w-4 h-4 animate-spin" />
                  <span>{t("common.loading")}</span>
                </div>
              ) : runTab === "events" ? (
                runDetails.events.length === 0 ? (
                  <div className="py-8 text-center text-ink-muted">{t("common.noData")}</div>
                ) : (
                  runDetails.events.map((ev, idx) => (
                    <div key={`${ev.event_id || "ev"}-${idx}`} className="p-3 rounded bg-elevated border border-border-subtle space-y-1">
                      <div className="font-mono text-sentinel-primary font-semibold ltr-isolate">
                        {ev.event_type || "EVENT"}
                      </div>
                      <pre className="ltr-isolate font-mono text-[11px] text-ink-secondary overflow-x-auto">
                        {JSON.stringify(ev.payload || {}, null, 2)}
                      </pre>
                    </div>
                  ))
                )
              ) : runTab === "evidence" ? (
                runDetails.evidence.length === 0 ? (
                  <div className="py-8 text-center text-ink-muted">{t("common.noData")}</div>
                ) : (
                  runDetails.evidence.map((evi, idx) => (
                    <div key={`${evi.evidence_id || "evi"}-${idx}`} className="p-3 rounded bg-elevated border border-border-subtle space-y-1">
                      <div className="flex justify-between font-mono">
                        <span className="text-sentinel-success">{evi.evidence_type} · {evi.source_tool}</span>
                        <span>{Math.round((evi.confidence || 0) * 100)}%</span>
                      </div>
                      <pre className="ltr-isolate font-mono text-[11px] text-ink-secondary whitespace-pre-wrap break-all">
                        {evi.sanitized_content || ""}
                      </pre>
                    </div>
                  ))
                )
              ) : runDetails.findings.length === 0 ? (
                <div className="py-8 text-center text-ink-muted">{t("common.noData")}</div>
              ) : (
                runDetails.findings.map((fd, idx) => (
                  <div key={`${fd.evidence_id || fd.title || "fd"}-${idx}`} className="p-3 rounded bg-elevated border border-border-subtle space-y-1">
                    <div className="font-semibold text-ink-primary">{fd.title}</div>
                    <div className="font-mono text-sentinel-warning ltr-isolate">{fd.affected_asset}</div>
                    <div className="font-mono text-[11px] text-ink-secondary whitespace-pre-wrap break-all">
                      {fd.evidence || ""}
                    </div>
                  </div>
                ))
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
