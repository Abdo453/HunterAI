"use client";

import React, { useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  Rocket,
  Play,
  Pause,
  Square,
  RotateCcw,
  Eye,
  X,
  Loader2,
  AlertCircle,
  CheckCircle2,
  Activity,
  Search,
  ChevronLeft,
  ChevronRight,
  Bookmark,
} from "lucide-react";
import StatsCards from "@/components/StatsCards";
import HardwareTelemetryCard from "@/components/HardwareTelemetryCard";
import TokenCostPanel from "@/components/TokenCostPanel";
import TaskSubtaskTree from "@/components/TaskSubtaskTree";
import ApprovalsPanel from "@/components/ApprovalsPanel";
import LiveConsole from "@/components/LiveConsole";
import TargetPresetStrip from "@/components/TargetPresetStrip";
import {
  MissionLaunchInput,
  RunRecord,
  usePlatform,
  validateScanTarget,
} from "@/lib/platform-context";
import { normalizeRunProgressPercent } from "@/lib/api-types";
import { TargetPreset } from "@/lib/target-presets";
import { useI18n } from "@/lib/i18n";
import { useFocusTrap } from "@/hooks/use-focus-trap";
import { sanitizePlainTerminalText } from "@/lib/terminal-sanitizer";

interface RunDetailsData {
  events: Array<{ event_id?: string; event_type?: string; timestamp?: number | string; payload?: Record<string, unknown> }>;
  evidence: Array<{ evidence_id?: string; source_tool?: string; evidence_type?: string; confidence?: number; sanitized_content?: string }>;
  findings: Array<{ evidence_id?: string; title?: string; affected_asset?: string; confidence?: number; verification_status?: string; evidence?: string }>;
}

const RUN_KINDS: Array<{ id: MissionLaunchInput["kind"]; labelKey: string }> = [
  { id: "omni", labelKey: "runs.kindOmni" },
  { id: "pipeline", labelKey: "runs.kindPipeline" },
  { id: "mission", labelKey: "runs.kindMission" },
  { id: "engine", labelKey: "runs.kindEngine" },
  { id: "go_core", labelKey: "runs.kindGoCore" },
];

const ARCHIVE_PAGE_SIZE = 8;

function statusPillClass(status: string): string {
  const norm = status.toLowerCase();
  if (norm === "running") {
    return "bg-sentinel-primary/15 text-sentinel-primary border-sentinel-primary/35";
  }
  if (norm === "paused" || norm === "pending" || norm === "interrupted") {
    return "bg-sentinel-warning/15 text-sentinel-warning border-sentinel-warning/35";
  }
  if (norm === "completed") {
    return "bg-sentinel-success/15 text-sentinel-success border-sentinel-success/35";
  }
  return "bg-sentinel-danger/15 text-sentinel-danger border-sentinel-danger/35";
}

export default function OverviewPage() {
  const {
    selectedEngagement,
    engagementSelectionSeq,
    targetDomain,
    runs,
    activeRunId,
    setActiveRunId,
    isScanning,
    launchMission,
    controlRun,
    recoverRun,
    apiJson,
  } = usePlatform();
  const { t, dir } = useI18n();

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
  const [runControlError, setRunControlError] = useState<string>("");
  const [runControlBusyId, setRunControlBusyId] = useState<string | null>(null);

  // Paginated Mission Archive (?q=&page=)
  const [archiveQuery, setArchiveQuery] = useState<string>("");
  const [archivePage, setArchivePage] = useState<number>(1);
  const [splitPercent, setSplitPercent] = useState<number>(55);
  const splitContainerRef = useRef<HTMLDivElement | null>(null);

  const [inspectedRun, setInspectedRun] = useState<RunRecord | null>(null);
  const [runTab, setRunTab] = useState<"events" | "evidence" | "findings">("events");
  const [runDetails, setRunDetails] = useState<RunDetailsData>({ events: [], evidence: [], findings: [] });
  const [runLoading, setRunLoading] = useState<boolean>(false);

  const runDrawerTrapRef = useFocusTrap(Boolean(inspectedRun), () => setInspectedRun(null));

  const lastSyncedEngIdRef = useRef<string>("");
  const userEditedOverviewTargetRef = useRef<boolean>(false);
  const lastManualPickSeqRef = useRef<number>(engagementSelectionSeq);

  // Hydrate initial ?q= and ?page= archive query params cleanly
  useEffect(() => {
    try {
      const params = new URLSearchParams(window.location.search);
      const q = params.get("q");
      const p = Number.parseInt(params.get("page") || "1", 10);
      if (q) setArchiveQuery(q);
      if (Number.isFinite(p) && p >= 1) setArchivePage(p);
    } catch {
      // Ignore query errors
    }
  }, []);

  useEffect(() => {
    if (engagementSelectionSeq !== lastManualPickSeqRef.current) {
      lastManualPickSeqRef.current = engagementSelectionSeq;
      userEditedOverviewTargetRef.current = false;
      const engId = selectedEngagement?.id || "";
      lastSyncedEngIdRef.current = engId;
      if (selectedEngagement?.target) {
        setTarget(selectedEngagement.target);
      }
      return;
    }

    const engId = selectedEngagement?.id || "";
    if (!engId) {
      lastSyncedEngIdRef.current = "";
      return;
    }
    if (engId !== lastSyncedEngIdRef.current) {
      lastSyncedEngIdRef.current = engId;
      if (selectedEngagement?.target && !userEditedOverviewTargetRef.current) {
        setTarget(selectedEngagement.target);
      }
    }
  }, [selectedEngagement, engagementSelectionSeq]);

  const handleLaunch = async (e: React.FormEvent) => {
    e.preventDefault();
    userEditedOverviewTargetRef.current = true;
    setLaunchError("");
    setLaunchFeedback("");

    if (kind !== "engine" || target.trim()) {
      const check = validateScanTarget(target);
      if (!check.valid) {
        setLaunchError(
          t(check.reason === "empty" ? "nav.scopeInvalidEmpty" : "nav.scopeFormatHint")
        );
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
      setLaunchError(res.error || t("runs.launchFailed"));
      return;
    }
    setLaunchFeedback(
      res.run?.run_id
        ? t("runs.startedRun", { id: res.run.run_id })
        : t("runs.dispatchedOk")
    );
  };

  const handleRunControl = useCallback(
    async (runId: string, action: "pause" | "resume" | "stop" | "recover") => {
      setRunControlError("");
      setRunControlBusyId(runId);
      try {
        const res =
          action === "recover" ? await recoverRun(runId) : await controlRun(runId, action);
        if (!res.ok) {
          setRunControlError(res.error || t("runs.controlFailed"));
        }
      } finally {
        setRunControlBusyId(null);
      }
    },
    [controlRun, recoverRun, t]
  );

  const inspectRunDetails = async (run: RunRecord) => {
    setInspectedRun(run);
    setActiveRunId(run.run_id);
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

  const filteredRuns = useMemo(() => {
    const q = archiveQuery.trim().toLowerCase();
    if (!q) return runs;
    return runs.filter(
      (r) =>
        (r.run_id || "").toLowerCase().includes(q) ||
        (r.target || "").toLowerCase().includes(q) ||
        (r.kind || "").toLowerCase().includes(q) ||
        (r.current_phase || "").toLowerCase().includes(q) ||
        (r.status || "").toLowerCase().includes(q)
    );
  }, [runs, archiveQuery]);

  const totalPages = Math.max(1, Math.ceil(filteredRuns.length / ARCHIVE_PAGE_SIZE));
  const safePage = Math.min(archivePage, totalPages);
  const pageRuns = useMemo(() => {
    const start = (safePage - 1) * ARCHIVE_PAGE_SIZE;
    return filteredRuns.slice(start, start + ARCHIVE_PAGE_SIZE);
  }, [filteredRuns, safePage]);

  const handleSplitPointerDown = (e: React.PointerEvent<HTMLDivElement>) => {
    e.preventDefault();
    const rect = splitContainerRef.current?.getBoundingClientRect();
    if (!rect || rect.width <= 0) return;

    const onMove = (moveEv: PointerEvent) => {
      const relX =
        dir === "rtl" ? rect.right - moveEv.clientX : moveEv.clientX - rect.left;
      const pct = Math.min(72, Math.max(32, Math.round((relX / rect.width) * 100)));
      setSplitPercent(pct);
    };
    const onUp = () => {
      window.removeEventListener("pointermove", onMove);
      window.removeEventListener("pointerup", onUp);
    };
    window.addEventListener("pointermove", onMove);
    window.addEventListener("pointerup", onUp);
  };

  const handleSplitKeyDown = (e: React.KeyboardEvent<HTMLDivElement>) => {
    const step = 4;
    if (e.key === "ArrowLeft") {
      e.preventDefault();
      setSplitPercent((p) => Math.min(72, Math.max(32, p + (dir === "rtl" ? step : -step))));
    } else if (e.key === "ArrowRight") {
      e.preventDefault();
      setSplitPercent((p) => Math.min(72, Math.max(32, p + (dir === "rtl" ? -step : step))));
    }
  };

  return (
    <div className="space-y-5">
      <StatsCards />

      {/* Live Hardware Telemetry + Persisted Token & Cost Analytics */}
      <div className="grid grid-cols-1 xl:grid-cols-12 gap-5">
        <div className="xl:col-span-5">
          <HardwareTelemetryCard compact />
        </div>
        <div className="xl:col-span-7">
          <TokenCostPanel runId={activeRunId} />
        </div>
      </div>

      {/* Unified Mission Launcher */}
      <section aria-labelledby="mission-launcher-heading" className="sentinel-surface p-4 space-y-3">
        <div className="flex flex-wrap items-center justify-between gap-2 pb-3 border-b border-border-subtle">
          <div className="flex items-center gap-2">
            <Rocket className="w-4 h-4 text-sentinel-primary" />
            <h1 id="mission-launcher-heading" className="text-sm font-semibold text-ink-primary">
              {t("runs.title")}
            </h1>
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
                {t(item.labelKey)}
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
              list="target-example-presets"
              value={target}
              onChange={(e) => {
                userEditedOverviewTargetRef.current = true;
                setTarget(e.target.value);
              }}
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
              {t("runs.proxyOptional")}
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
              className="w-full min-h-[44px] sm:min-h-[36px] px-3 rounded-md bg-sentinel-primary text-sentinel-onAccent text-xs font-semibold flex items-center justify-center gap-1.5 hover:opacity-90 disabled:opacity-50"
            >
              {isScanning ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Play className="w-3.5 h-3.5" />}
              <span>{t("runs.launchMission")}</span>
            </button>
          </div>

          {kind === "engine" && (
            <>
              <div className="md:col-span-3 space-y-1">
                <label htmlFor="overview-engine" className="text-xs text-ink-muted">
                  {t("runs.cliEngineLabel")}
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
                  {t("runs.taskPromptLabel")}
                </label>
                <input
                  id="overview-prompt"
                  type="text"
                  value={prompt}
                  onChange={(e) => setPrompt(e.target.value)}
                  placeholder={t("runs.taskPromptPlaceholder")}
                  className="w-full h-9 px-3 rounded-md bg-inset border border-border-subtle text-xs text-ink-primary"
                />
              </div>
              <div className="md:col-span-2 space-y-1">
                <label htmlFor="overview-cov" className="text-xs text-ink-muted">
                  {t("runs.coverageTargetLabel")}
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

        <TargetPresetStrip
          testId="overview-target-presets"
          heading={t("runs.presetsHeading")}
          subtitle={t("runs.presetsHint")}
          activeTarget={target}
          onSelect={(preset: TargetPreset) => {
            userEditedOverviewTargetRef.current = true;
            setTarget(preset.target);
            if (launchError) setLaunchError("");
            if (launchFeedback) setLaunchFeedback("");
          }}
        />

        {launchError && (
          <div role="alert" className="px-3 py-2 rounded bg-sentinel-danger/10 border border-sentinel-danger/40 text-sentinel-danger text-xs flex items-center gap-2">
            <AlertCircle className="w-4 h-4 shrink-0" />
            <span>{launchError}</span>
          </div>
        )}
        {launchFeedback && (
          <div role="status" className="px-3 py-2 rounded bg-sentinel-success/10 border border-sentinel-success/40 text-sentinel-success text-xs flex items-center gap-2">
            <CheckCircle2 className="w-4 h-4 shrink-0" />
            <span className="font-mono">{launchFeedback}</span>
          </div>
        )}
      </section>

      {/* Split Resizable Mission Workspace: Paginated Mission Archive <-> Flow->Task->Subtask Tree */}
      <div
        ref={splitContainerRef}
        data-testid="mission-split-workspace"
        className="flex flex-col xl:flex-row gap-4 xl:gap-0 items-stretch"
      >
        <section
          style={{ flexBasis: `${splitPercent}%` }}
          className="xl:min-w-0 sentinel-surface p-4 flex flex-col gap-3"
        >
          <div className="flex flex-wrap items-center justify-between gap-2 pb-2 border-b border-border-subtle">
            <div className="flex items-center gap-2">
              <Activity className="w-4 h-4 text-sentinel-primary" />
              <h2 className="text-sm font-semibold text-ink-primary">{t("runs.archiveTitle")}</h2>
              <span className="text-xs font-mono tabular-nums px-2 py-0.5 rounded bg-elevated border border-border-subtle text-ink-secondary">
                {filteredRuns.length}
              </span>
            </div>
            <div className="relative flex-1 sm:flex-initial sm:w-56">
              <Search className="w-3.5 h-3.5 text-ink-muted absolute start-2.5 top-1/2 -translate-y-1/2 pointer-events-none" />
              <input
                type="search"
                value={archiveQuery}
                onChange={(e) => {
                  setArchiveQuery(e.target.value);
                  setArchivePage(1);
                }}
                placeholder={t("runs.searchArchivePlaceholder")}
                aria-label={t("runs.searchArchivePlaceholder")}
                className="w-full h-8 ps-8 pe-2.5 rounded bg-inset border border-border-subtle text-xs text-ink-primary placeholder:text-ink-muted"
              />
            </div>
          </div>

          {runControlError && (
            <div role="alert" className="px-3 py-2 rounded bg-sentinel-danger/10 border border-sentinel-danger/40 text-sentinel-danger text-xs flex items-center gap-2">
              <AlertCircle className="w-4 h-4 shrink-0" />
              <span>{runControlError}</span>
            </div>
          )}

          {pageRuns.length === 0 ? (
            <div className="py-8 text-center text-xs text-ink-muted">{t("runs.emptyRuns")}</div>
          ) : (
            <div className="overflow-x-auto border border-border-subtle rounded-md bg-inset">
              <table className="w-full text-xs border-collapse">
                <thead className="bg-elevated border-b border-border-subtle text-ink-muted">
                  <tr>
                    <th className="py-2 px-3 text-start font-semibold">{t("runs.colRunId")}</th>
                    <th className="py-2 px-3 text-start font-semibold">{t("runs.colKind")}</th>
                    <th className="py-2 px-3 text-start font-semibold">{t("common.target")}</th>
                    <th className="py-2 px-3 text-start font-semibold">{t("runs.activePhase")}</th>
                    <th className="py-2 px-3 text-start font-semibold">{t("common.status")}</th>
                    <th className="py-2 px-3 text-start font-semibold">{t("common.actions")}</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-border-subtle">
                  {pageRuns.map((run, idx) => {
                    const st = (run.status || "").toLowerCase();
                    const pct = normalizeRunProgressPercent(run.progress);
                    const isBusy = runControlBusyId === run.run_id;
                    const canRecover =
                      Boolean(run.recoverable) ||
                      ["paused", "interrupted", "failed", "stopped"].includes(st);
                    return (
                      <tr
                        key={`${run.run_id || "run"}-${idx}`}
                        className={`hover:bg-elevated/60 ${activeRunId === run.run_id ? "bg-sentinel-primary/5" : ""}`}
                      >
                        <td className="py-2 px-3 font-mono text-ink-primary ltr-isolate whitespace-nowrap">
                          <div className="flex items-center gap-1.5">
                            <span>{run.run_id}</span>
                            {run.checkpoint_id && (
                              <span
                                title={run.checkpoint_id}
                                className="inline-flex items-center gap-0.5 px-1.5 py-0.5 rounded bg-sentinel-ai/15 text-sentinel-ai border border-sentinel-ai/35 text-[10px]"
                              >
                                <Bookmark className="w-2.5 h-2.5" />
                                <span>{t("runs.checkpointBadge")}</span>
                              </span>
                            )}
                          </div>
                        </td>
                        <td className="py-2 px-3 font-mono text-sentinel-primary uppercase whitespace-nowrap">
                          {run.kind}
                        </td>
                        <td className="py-2 px-3 font-mono text-ink-secondary ltr-isolate max-w-[160px] truncate">
                          {run.target || "—"}
                        </td>
                        <td className="py-2 px-3 font-mono text-ink-muted tabular-nums whitespace-nowrap">
                          <span>{run.current_phase || "—"}</span>
                          {typeof run.progress === "number" && (
                            <span className="ms-1 text-ink-primary">({pct}%)</span>
                          )}
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
                                disabled={isBusy}
                                onClick={() => void handleRunControl(run.run_id, "pause")}
                                aria-label={t("runs.pauseRun")}
                                title={t("runs.pauseRun")}
                                className="h-7 px-2 rounded border border-border-subtle bg-elevated hover:border-border-strong text-ink-primary disabled:opacity-40"
                              >
                                <Pause className="w-3.5 h-3.5 text-sentinel-warning" />
                              </button>
                            )}
                            {st === "paused" && (
                              <button
                                type="button"
                                disabled={isBusy}
                                onClick={() => void handleRunControl(run.run_id, "resume")}
                                aria-label={t("runs.resumeRun")}
                                title={t("runs.resumeRun")}
                                className="h-7 px-2 rounded border border-border-subtle bg-elevated hover:border-border-strong text-ink-primary disabled:opacity-40"
                              >
                                <Play className="w-3.5 h-3.5 text-sentinel-success" />
                              </button>
                            )}
                            {["running", "paused", "pending"].includes(st) && (
                              <button
                                type="button"
                                disabled={isBusy}
                                onClick={() => void handleRunControl(run.run_id, "stop")}
                                aria-label={t("runs.stopRun")}
                                title={t("runs.stopRun")}
                                className="h-7 px-2 rounded border border-border-subtle bg-elevated hover:border-border-strong text-ink-primary disabled:opacity-40"
                              >
                                <Square className="w-3.5 h-3.5 text-sentinel-danger" />
                              </button>
                            )}
                            {canRecover && (
                              <button
                                type="button"
                                disabled={isBusy}
                                onClick={() => void handleRunControl(run.run_id, "recover")}
                                aria-label={t("runs.recoverRun")}
                                title={t("runs.recoverRun")}
                                className="h-7 px-2 rounded border border-sentinel-primary/40 bg-sentinel-primary/15 text-sentinel-primary hover:bg-sentinel-primary/25 flex items-center gap-1 disabled:opacity-40"
                              >
                                <RotateCcw className="w-3 h-3" />
                                <span className="hidden sm:inline">{t("runs.recoverRun")}</span>
                              </button>
                            )}
                            <button
                              type="button"
                              onClick={() => void inspectRunDetails(run)}
                              aria-label={`${t("common.details")} ${run.run_id}`}
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

          {/* Archive Pagination */}
          {totalPages > 1 && (
            <div className="flex items-center justify-between gap-2 pt-1 text-xs">
              <span className="font-mono text-ink-muted tabular-nums">
                {t("graph.pageOf", { page: safePage, total: totalPages })}
              </span>
              <div className="flex items-center gap-1.5">
                <button
                  type="button"
                  disabled={safePage <= 1}
                  onClick={() => setArchivePage((p) => Math.max(1, p - 1))}
                  className="h-7 px-2.5 rounded border border-border-subtle bg-elevated text-ink-primary disabled:opacity-40 flex items-center gap-1"
                >
                  <ChevronLeft className="w-3.5 h-3.5 rtl:rotate-180" />
                  <span>{t("graph.prevPage")}</span>
                </button>
                <button
                  type="button"
                  disabled={safePage >= totalPages}
                  onClick={() => setArchivePage((p) => Math.min(totalPages, p + 1))}
                  className="h-7 px-2.5 rounded border border-border-subtle bg-elevated text-ink-primary disabled:opacity-40 flex items-center gap-1"
                >
                  <span>{t("graph.nextPage")}</span>
                  <ChevronRight className="w-3.5 h-3.5 rtl:rotate-180" />
                </button>
              </div>
            </div>
          )}
        </section>

        {/* Desktop Resizable Split Divider */}
        <div
          role="separator"
          aria-orientation="vertical"
          aria-label={t("runs.resizeWorkspace")}
          tabIndex={0}
          onPointerDown={handleSplitPointerDown}
          onKeyDown={handleSplitKeyDown}
          className="hidden xl:flex w-3 shrink-0 cursor-col-resize items-center justify-center group"
        >
          <div className="w-1 h-16 rounded-full bg-border-subtle group-hover:bg-sentinel-primary transition-colors" />
        </div>

        <div style={{ flexBasis: `${100 - splitPercent}%` }} className="xl:min-w-0 flex flex-col">
          <TaskSubtaskTree />
        </div>
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
            ref={runDrawerTrapRef}
            role="dialog"
            aria-modal="true"
            aria-label={`${t("runs.colRunId")} ${inspectedRun.run_id}`}
            tabIndex={-1}
            onClick={(e) => e.stopPropagation()}
            className="w-full max-w-2xl h-full bg-surface border-s border-border-strong shadow-sentinelMd flex flex-col overflow-hidden"
          >
            <div className="px-5 py-4 border-b border-border-subtle flex items-center justify-between gap-3">
              <div className="min-w-0">
                <div className="text-xs font-mono text-sentinel-primary ltr-isolate">
                  {inspectedRun.kind} · {inspectedRun.run_id} ·{" "}
                  {normalizeRunProgressPercent(inspectedRun.progress)}%
                </div>
                <h3 className="text-sm font-semibold text-ink-primary truncate ltr-isolate">
                  {inspectedRun.target || inspectedRun.run_id}
                </h3>
              </div>
              <button
                type="button"
                onClick={() => setInspectedRun(null)}
                aria-label={t("common.close")}
                className="min-h-[44px] min-w-[44px] sm:min-h-[36px] sm:min-w-[36px] rounded border border-border-subtle bg-elevated text-ink-primary flex items-center justify-center"
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
                      ? "bg-sentinel-primary/15 text-sentinel-primary border border-sentinel-primary/40"
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
                        {sanitizePlainTerminalText(JSON.stringify(ev.payload || {}, null, 2))}
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
                        {sanitizePlainTerminalText(evi.sanitized_content || "")}
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
                      {sanitizePlainTerminalText(fd.evidence || "")}
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
