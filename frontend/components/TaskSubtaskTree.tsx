"use client";

import React, { useEffect, useMemo, useState } from "react";
import { ChevronRight, ChevronDown, Search, Layers, CheckCircle2, Clock, AlertCircle, Play } from "lucide-react";
import { MissionRun, TaskRecord, normalizeRunProgressPercent } from "@/lib/api-types";
import { usePlatform } from "@/lib/platform-context";
import { useI18n } from "@/lib/i18n";

interface FlowTaskTreeItem {
  id: string;
  label: string;
  subtitle: string;
  status: string;
  progressPct?: number;
  children: Array<{
    id: string;
    title: string;
    role: string;
    status: string;
    summary?: string;
    subtasks: Array<{
      id: string;
      title: string;
      status: string;
      result?: string;
    }>;
  }>;
}

function statusBadge(status: string): string {
  const s = status.toLowerCase();
  if (s === "running" || s === "in_progress") {
    return "bg-sentinel-primary/15 text-sentinel-primary border-sentinel-primary/35";
  }
  if (s === "completed" || s === "done" || s === "finished") {
    return "bg-sentinel-success/15 text-sentinel-success border-sentinel-success/35";
  }
  if (s === "paused" || s === "pending" || s === "queued" || s === "waiting") {
    return "bg-sentinel-warning/15 text-sentinel-warning border-sentinel-warning/35";
  }
  return "bg-sentinel-danger/15 text-sentinel-danger border-sentinel-danger/35";
}

function StatusGlyph({ status }: { status: string }) {
  const s = status.toLowerCase();
  if (s === "completed" || s === "done") return <CheckCircle2 className="w-3.5 h-3.5 text-sentinel-success shrink-0" />;
  if (s === "running") return <Play className="w-3.5 h-3.5 text-sentinel-primary shrink-0" />;
  if (s === "failed" || s === "error") return <AlertCircle className="w-3.5 h-3.5 text-sentinel-danger shrink-0" />;
  return <Clock className="w-3.5 h-3.5 text-sentinel-warning shrink-0" />;
}

export default function TaskSubtaskTree({
  runsOverride,
  tasksOverride,
}: {
  runsOverride?: MissionRun[];
  tasksOverride?: TaskRecord[];
}) {
  const { runs: ctxRuns, tasks: ctxTasks, activeTaskFilter, setActiveTaskFilter } = usePlatform();
  const { t } = useI18n();

  const runs = runsOverride ?? ctxRuns;
  const tasks = tasksOverride ?? ctxTasks;

  const [rawSearch, setRawSearch] = useState<string>("");
  const [debouncedQuery, setDebouncedQuery] = useState<string>("");
  const [expanded, setExpanded] = useState<Record<string, boolean>>({});

  // 500ms debounced search auto-expand
  useEffect(() => {
    const timer = window.setTimeout(() => {
      setDebouncedQuery(rawSearch.trim().toLowerCase());
    }, 500);
    return () => window.clearTimeout(timer);
  }, [rawSearch]);

  const flows = useMemo<FlowTaskTreeItem[]>(() => {
    const items: FlowTaskTreeItem[] = [];
    const claimedTaskIds = new Set<string>();

    for (const run of runs.slice(0, 20)) {
      const matchedTasks = tasks.filter(
        (tk) => tk.run_id === run.run_id || (run.engagement_id && tk.engagement_id === run.engagement_id)
      );
      matchedTasks.forEach((tk) => claimedTaskIds.add(tk.id));

      const metaSubtasks = Array.isArray(run.meta?.subtasks)
        ? (run.meta?.subtasks as Array<Record<string, unknown>>)
        : [];
      const metaPhases = Array.isArray(run.meta?.phases)
        ? (run.meta?.phases as Array<Record<string, unknown>>)
        : [];

      const children: FlowTaskTreeItem["children"] = matchedTasks.map((tk) => ({
        id: tk.id,
        title: tk.title || tk.agent_role,
        role: tk.agent_role,
        status: tk.status,
        summary: Object.entries(tk.output_summary || {})
          .slice(0, 2)
          .map(([k, v]) => `${k}: ${String(v)}`)
          .join(" · "),
        subtasks: (tk.subtasks || []).map((st) => ({
          id: st.subtask_id,
          title: st.title,
          status: st.status,
          result: st.result,
        })),
      }));

      if (children.length === 0 && (metaPhases.length > 0 || run.current_phase)) {
        const phaseId = `${run.run_id}:phase:${run.current_phase || "init"}`;
        children.push({
          id: phaseId,
          title: run.current_phase || t("runs.phaseInit"),
          role: run.kind,
          status: run.status,
          subtasks: metaSubtasks.map((st, idx) => ({
            id: String(st.subtask_id || `${phaseId}:sub:${idx}`),
            title: String(st.title || st.name || `Subtask ${idx + 1}`),
            status: String(st.status || run.status),
            result: typeof st.result === "string" ? st.result : undefined,
          })),
        });
      }

      items.push({
        id: run.run_id,
        label: `${run.kind} · ${run.target || run.run_id}`,
        subtitle: run.run_id,
        status: run.canonical_status || run.status,
        progressPct: normalizeRunProgressPercent(run.progress),
        children,
      });
    }

    const orphanTasks = tasks.filter((tk) => !claimedTaskIds.has(tk.id));
    if (orphanTasks.length > 0) {
      items.push({
        id: "go-core-workers",
        label: t("taskTree.goWorkerGroup"),
        subtitle: "artex-go-core",
        status: orphanTasks.some((tk) => tk.status.toUpperCase() === "RUNNING") ? "RUNNING" : "QUEUED",
        children: orphanTasks.map((tk) => ({
          id: tk.id,
          title: tk.title || tk.agent_role,
          role: tk.agent_role,
          status: tk.status,
          summary: Object.entries(tk.output_summary || {})
            .slice(0, 2)
            .map(([k, v]) => `${k}: ${String(v)}`)
            .join(" · "),
          subtasks: (tk.subtasks || []).map((st) => ({
            id: st.subtask_id,
            title: st.title,
            status: st.status,
            result: st.result,
          })),
        })),
      });
    }

    return items;
  }, [runs, tasks, t]);

  const filteredFlows = useMemo(() => {
    if (!debouncedQuery) return flows;
    return flows
      .map((flow) => {
        const flowMatch =
          flow.label.toLowerCase().includes(debouncedQuery) ||
          flow.subtitle.toLowerCase().includes(debouncedQuery);
        const matchingChildren = flow.children
          .map((child) => {
            const childMatch =
              child.title.toLowerCase().includes(debouncedQuery) ||
              child.role.toLowerCase().includes(debouncedQuery);
            const matchingSubs = child.subtasks.filter(
              (s) =>
                s.title.toLowerCase().includes(debouncedQuery) ||
                (s.result || "").toLowerCase().includes(debouncedQuery)
            );
            if (childMatch || matchingSubs.length > 0 || flowMatch) {
              return { ...child, subtasks: childMatch || flowMatch ? child.subtasks : matchingSubs };
            }
            return null;
          })
          .filter((c): c is NonNullable<typeof c> => c !== null);

        if (flowMatch || matchingChildren.length > 0) {
          return { ...flow, children: matchingChildren };
        }
        return null;
      })
      .filter((f): f is FlowTaskTreeItem => f !== null);
  }, [flows, debouncedQuery]);

  // Auto-expand matching branches when search query resolves
  useEffect(() => {
    if (!debouncedQuery) return;
    const nextExpanded: Record<string, boolean> = {};
    for (const f of filteredFlows) {
      nextExpanded[f.id] = true;
      for (const c of f.children) {
        nextExpanded[c.id] = true;
      }
    }
    setExpanded((prev) => ({ ...prev, ...nextExpanded }));
  }, [debouncedQuery, filteredFlows]);

  const toggleNode = (id: string) => {
    setExpanded((prev) => ({ ...prev, [id]: !prev[id] }));
  };

  return (
    <section
      data-testid="task-subtask-tree"
      aria-labelledby="task-tree-heading"
      className="sentinel-surface p-4 flex flex-col gap-3"
    >
      <div className="flex flex-wrap items-center justify-between gap-2 pb-2 border-b border-border-subtle">
        <div className="flex items-center gap-2">
          <Layers className="w-4 h-4 text-sentinel-primary" />
          <h2 id="task-tree-heading" className="text-sm font-semibold text-ink-primary">
            {t("taskTree.title")}
          </h2>
          <span className="px-2 py-0.5 rounded-full text-[11px] font-mono tabular-nums bg-elevated border border-border-subtle text-ink-secondary">
            {filteredFlows.length}
          </span>
        </div>

        <div className="relative min-w-[180px] flex-1 sm:flex-initial">
          <Search className="w-3.5 h-3.5 text-ink-muted absolute top-1/2 -translate-y-1/2 start-2.5 pointer-events-none" />
          <input
            type="search"
            value={rawSearch}
            onChange={(e) => setRawSearch(e.target.value)}
            placeholder={t("taskTree.searchPlaceholder")}
            aria-label={t("taskTree.searchPlaceholder")}
            className="w-full h-8 ps-8 pe-3 rounded bg-inset border border-border-subtle text-xs text-ink-primary placeholder:text-ink-muted"
          />
        </div>
      </div>

      {filteredFlows.length === 0 ? (
        <div className="py-6 text-center text-xs text-ink-muted">{t("taskTree.empty")}</div>
      ) : (
        <div className="space-y-2 max-h-80 overflow-y-auto pe-1">
          {filteredFlows.map((flow) => {
            const isFlowOpen = expanded[flow.id] ?? true;
            return (
              <div key={flow.id} className="rounded-md border border-border-subtle bg-inset overflow-hidden">
                <div className="flex items-center justify-between gap-2 px-2.5 py-2 bg-elevated/60">
                  <button
                    type="button"
                    aria-expanded={isFlowOpen}
                    onClick={() => toggleNode(flow.id)}
                    className="flex items-center gap-2 min-w-0 flex-1 text-start text-xs font-semibold text-ink-primary hover:text-sentinel-primary"
                  >
                    {isFlowOpen ? (
                      <ChevronDown className="w-3.5 h-3.5 text-ink-muted shrink-0" />
                    ) : (
                      <ChevronRight className="w-3.5 h-3.5 text-ink-muted shrink-0 rtl:rotate-180" />
                    )}
                    <StatusGlyph status={flow.status} />
                    <span className="truncate ltr-isolate">{flow.label}</span>
                  </button>

                  <div className="flex items-center gap-1.5 shrink-0">
                    {typeof flow.progressPct === "number" && (
                      <span className="font-mono text-[10px] text-ink-muted tabular-nums">
                        {flow.progressPct}%
                      </span>
                    )}
                    <span className={`px-1.5 py-0.5 rounded border text-[10px] font-mono uppercase ${statusBadge(flow.status)}`}>
                      {flow.status}
                    </span>
                  </div>
                </div>

                {isFlowOpen && flow.children.length > 0 && (
                  <div className="p-2 space-y-1.5 border-t border-border-subtle">
                    {flow.children.map((task) => {
                      const isTaskOpen = expanded[task.id] ?? false;
                      const isFiltered = activeTaskFilter === task.id;
                      return (
                        <div
                          key={task.id}
                          className={`rounded border text-xs ${
                            isFiltered
                              ? "border-sentinel-primary bg-sentinel-primary/10"
                              : "border-border-subtle bg-surface"
                          }`}
                        >
                          <div className="flex items-center justify-between gap-2 px-2.5 py-1.5">
                            <button
                              type="button"
                              aria-expanded={isTaskOpen}
                              onClick={() => toggleNode(task.id)}
                              className="flex items-center gap-1.5 min-w-0 flex-1 text-start text-ink-primary hover:text-sentinel-primary"
                            >
                              {task.subtasks.length > 0 ? (
                                isTaskOpen ? (
                                  <ChevronDown className="w-3 h-3 text-ink-muted shrink-0" />
                                ) : (
                                  <ChevronRight className="w-3 h-3 text-ink-muted shrink-0 rtl:rotate-180" />
                                )
                              ) : (
                                <span className="w-3 h-3 shrink-0" />
                              )}
                              <span className="font-mono text-[11px] text-sentinel-primary shrink-0">
                                {task.role}
                              </span>
                              <span className="truncate">{task.title}</span>
                            </button>

                            <div className="flex items-center gap-1.5 shrink-0">
                              <button
                                type="button"
                                onClick={() =>
                                  setActiveTaskFilter(isFiltered ? "ALL" : task.id)
                                }
                                aria-pressed={isFiltered}
                                className={`px-1.5 py-0.5 rounded text-[10px] font-mono border ${
                                  isFiltered
                                    ? "border-sentinel-primary bg-sentinel-primary/15 text-sentinel-primary"
                                    : "border-border-subtle bg-elevated text-ink-muted hover:text-ink-primary"
                                }`}
                              >
                                {isFiltered ? t("taskTree.filtered") : t("common.filter")}
                              </button>
                              <span className={`px-1.5 py-0.5 rounded border text-[10px] font-mono uppercase ${statusBadge(task.status)}`}>
                                {task.status}
                              </span>
                            </div>
                          </div>

                          {task.summary && (
                            <div className="px-7 pb-1.5 text-[11px] font-mono text-ink-muted truncate ltr-isolate">
                              {task.summary}
                            </div>
                          )}

                          {isTaskOpen && task.subtasks.length > 0 && (
                            <ul className="px-6 pb-2 space-y-1 border-t border-border-subtle/60 pt-1.5">
                              {task.subtasks.map((sub) => (
                                <li
                                  key={sub.id}
                                  className="flex items-center justify-between gap-2 text-[11px] text-ink-secondary"
                                >
                                  <span className="truncate">{sub.title}</span>
                                  <span className={`px-1.5 py-0.5 rounded border text-[10px] font-mono uppercase shrink-0 ${statusBadge(sub.status)}`}>
                                    {sub.status}
                                  </span>
                                </li>
                              ))}
                            </ul>
                          )}
                        </div>
                      );
                    })}
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
