"use client";

import React, { useMemo, useRef, useState } from "react";
import {
  Terminal,
  RefreshCw,
  Pause,
  Play,
  Trash2,
  ChevronDown,
  ChevronUp,
  Search,
  Download,
  ArrowDown,
} from "lucide-react";
import { ConsoleEntry, ConsoleLevel, usePlatform } from "@/lib/platform-context";
import { useI18n } from "@/lib/i18n";
import { parseAnsiSegments, sanitizePlainTerminalText } from "@/lib/terminal-sanitizer";
import { useAutoScroll } from "@/hooks/use-auto-scroll";
import TaskFilterDropdown from "@/components/TaskFilterDropdown";

const LEVEL_FILTERS: Array<"ALL" | ConsoleLevel> = [
  "ALL",
  "INFO",
  "SUCCESS",
  "WARN",
  "ERROR",
  "AUDIT",
];

function levelStyle(level: ConsoleLevel): string {
  switch (level) {
    case "ERROR":
      return "text-sentinel-danger";
    case "SUCCESS":
      return "text-sentinel-success";
    case "WARN":
      return "text-sentinel-warning";
    case "AUDIT":
      return "text-sentinel-ai";
    default:
      return "text-sentinel-primary";
  }
}

const ConsoleRow = React.memo(function ConsoleRow({
  entry,
  highlighted,
}: {
  entry: ConsoleEntry;
  highlighted: boolean;
}) {
  const segments = useMemo(() => parseAnsiSegments(entry.message), [entry.message]);

  return (
    <div
      className={`leading-relaxed break-all px-1.5 py-0.5 rounded ${
        highlighted ? "bg-sentinel-warning/20 ring-1 ring-sentinel-warning/50" : ""
      }`}
    >
      <span className="text-ink-muted tabular-nums">[{entry.timestamp}]</span>{" "}
      <span className={`font-semibold ${levelStyle(entry.level)}`}>[{entry.level}]</span>{" "}
      <span className="text-ink-secondary">[{entry.source}]</span>{" "}
      <span className="text-ink-primary">
        {segments.map((seg, idx) => (
          <span
            key={idx}
            className={`${seg.colorClass || ""} ${seg.bold ? "font-bold" : ""}`}
          >
            {seg.text}
          </span>
        ))}
      </span>
    </div>
  );
});

export default function LiveConsole() {
  const {
    consoleLogs,
    streamPaused,
    setStreamPaused,
    clearConsoleLogs,
    refreshNow,
    activeTaskFilter,
  } = usePlatform();
  const { t } = useI18n();

  const [collapsed, setCollapsed] = useState<boolean>(false);
  const [levelFilter, setLevelFilter] = useState<"ALL" | ConsoleLevel>("ALL");
  const [searchQuery, setSearchQuery] = useState<string>("");
  const [activeMatchIdx, setActiveMatchIdx] = useState<number>(0);

  const rowRefs = useRef<Map<number, HTMLDivElement>>(new Map());

  const filteredLogs = useMemo(() => {
    return consoleLogs.filter((entry) => {
      if (levelFilter !== "ALL" && entry.level !== levelFilter) return false;
      if (activeTaskFilter && activeTaskFilter !== "ALL") {
        const matchTask =
          entry.taskId === activeTaskFilter ||
          entry.message.includes(activeTaskFilter) ||
          entry.source.includes(activeTaskFilter);
        if (!matchTask) return false;
      }
      return true;
    });
  }, [consoleLogs, levelFilter, activeTaskFilter]);

  const matchIndices = useMemo(() => {
    const q = searchQuery.trim().toLowerCase();
    if (!q) return [];
    const hits: number[] = [];
    filteredLogs.forEach((entry, idx) => {
      const plain = sanitizePlainTerminalText(
        `${entry.timestamp} ${entry.level} ${entry.source} ${entry.message}`
      ).toLowerCase();
      if (plain.includes(q)) hits.push(idx);
    });
    return hits;
  }, [filteredLogs, searchQuery]);

  const safeMatchIdx = matchIndices.length > 0 ? activeMatchIdx % matchIndices.length : 0;
  const activeLogRowIndex = matchIndices.length > 0 ? matchIndices[safeMatchIdx] : -1;

  const { containerRef, endRef, hasNewMessages, unreadCount, scrollToEnd } = useAutoScroll(
    filteredLogs,
    `${levelFilter}:${activeTaskFilter}`
  );

  const jumpToMatch = (delta: number) => {
    if (matchIndices.length === 0) return;
    const next = (safeMatchIdx + delta + matchIndices.length) % matchIndices.length;
    setActiveMatchIdx(next);
    const targetRow = rowRefs.current.get(matchIndices[next]);
    targetRow?.scrollIntoView({ behavior: "smooth", block: "center" });
  };

  const handleDownloadLogs = () => {
    const content = filteredLogs
      .map(
        (e) =>
          `[${e.timestamp}] [${e.level}] [${e.source}] ${sanitizePlainTerminalText(e.message)}`
      )
      .join("\n");
    const blob = new Blob([content], { type: "text/plain;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `artex-console-${Date.now()}.log`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  return (
    <section
      data-testid="live-console"
      aria-labelledby="live-console-heading"
      className="sentinel-surface p-4 flex flex-col gap-3"
    >
      <div className="flex flex-wrap items-center justify-between gap-2 pb-2 border-b border-border-subtle">
        <div className="flex items-center gap-2">
          <button
            type="button"
            onClick={() => setCollapsed((prev) => !prev)}
            aria-expanded={!collapsed}
            className="flex items-center gap-2 text-start text-ink-primary hover:text-sentinel-primary transition-colors"
          >
            {collapsed ? (
              <ChevronDown className="w-4 h-4 text-ink-muted" />
            ) : (
              <ChevronUp className="w-4 h-4 text-ink-muted" />
            )}
            <Terminal className="w-4 h-4 text-sentinel-primary" />
            <h2
              id="live-console-heading"
              className="text-xs font-semibold uppercase tracking-wider font-mono"
            >
              {t("console.title")}
            </h2>
          </button>

          {streamPaused && (
            <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-sentinel-warning/15 text-sentinel-warning border border-sentinel-warning/35">
              {t("console.pausedLabel")}
            </span>
          )}
        </div>

        <div className="flex flex-wrap items-center gap-1.5">
          <TaskFilterDropdown />

          <button
            type="button"
            onClick={() => setStreamPaused((prev) => !prev)}
            className="h-8 px-2.5 rounded border border-border-subtle bg-elevated hover:border-border-strong text-xs text-ink-secondary hover:text-ink-primary flex items-center gap-1"
          >
            {streamPaused ? (
              <>
                <Play className="w-3 h-3 text-sentinel-success" />
                <span>{t("console.resumeStream")}</span>
              </>
            ) : (
              <>
                <Pause className="w-3 h-3 text-sentinel-warning" />
                <span>{t("console.pauseStream")}</span>
              </>
            )}
          </button>

          <button
            type="button"
            disabled={filteredLogs.length === 0}
            onClick={handleDownloadLogs}
            aria-label={t("logs.downloadLogs")}
            title={t("logs.downloadLogs")}
            className="h-8 px-2.5 rounded border border-border-subtle bg-elevated hover:border-border-strong text-xs text-ink-secondary hover:text-ink-primary flex items-center gap-1 disabled:opacity-40"
          >
            <Download className="w-3 h-3" />
            <span className="hidden sm:inline">{t("logs.downloadLogs")}</span>
          </button>

          <button
            type="button"
            onClick={clearConsoleLogs}
            className="h-8 px-2.5 rounded border border-border-subtle bg-elevated hover:border-border-strong text-xs text-ink-secondary hover:text-ink-primary flex items-center gap-1"
          >
            <Trash2 className="w-3 h-3" />
            <span>{t("console.clearBtn")}</span>
          </button>

          <button
            type="button"
            onClick={() => void refreshNow()}
            aria-label={t("common.refresh")}
            className="h-8 px-2.5 rounded border border-border-subtle bg-elevated hover:border-border-strong text-xs text-ink-secondary hover:text-ink-primary flex items-center gap-1"
          >
            <RefreshCw className="w-3 h-3" />
          </button>
        </div>
      </div>

      {!collapsed && (
        <>
          <div className="flex flex-wrap items-center justify-between gap-2">
            <div
              role="group"
              aria-label={t("console.title")}
              className="flex flex-wrap items-center gap-1 bg-inset p-0.5 rounded border border-border-subtle"
            >
              {LEVEL_FILTERS.map((lvl) => (
                <button
                  key={lvl}
                  type="button"
                  onClick={() => setLevelFilter(lvl)}
                  aria-pressed={levelFilter === lvl}
                  className={`px-2 py-0.5 rounded text-[11px] font-mono transition-colors ${
                    levelFilter === lvl
                      ? "bg-elevated text-ink-primary border border-border-subtle"
                      : "text-ink-muted hover:text-ink-primary"
                  }`}
                >
                  {lvl === "ALL" ? t("console.levelAll") : lvl}
                </button>
              ))}
            </div>

            <div className="flex items-center gap-1.5 flex-1 sm:flex-initial min-w-[200px]">
              <div className="relative flex-1">
                <Search className="w-3.5 h-3.5 text-ink-muted absolute top-1/2 -translate-y-1/2 start-2.5 pointer-events-none" />
                <input
                  type="search"
                  value={searchQuery}
                  onChange={(e) => {
                    setSearchQuery(e.target.value);
                    setActiveMatchIdx(0);
                  }}
                  placeholder={t("console.searchPlaceholder")}
                  aria-label={t("console.searchPlaceholder")}
                  className="w-full h-8 ps-8 pe-3 rounded bg-inset border border-border-subtle text-xs text-ink-primary placeholder:text-ink-muted"
                />
              </div>
              {searchQuery.trim() && (
                <div className="flex items-center gap-1 text-[11px] font-mono text-ink-muted shrink-0">
                  <span className="tabular-nums">
                    {matchIndices.length > 0 ? `${safeMatchIdx + 1}/${matchIndices.length}` : "0/0"}
                  </span>
                  <button
                    type="button"
                    disabled={matchIndices.length === 0}
                    onClick={() => jumpToMatch(-1)}
                    aria-label={t("console.prevMatch")}
                    className="h-7 w-7 rounded border border-border-subtle bg-elevated text-ink-primary flex items-center justify-center disabled:opacity-40"
                  >
                    <ChevronUp className="w-3.5 h-3.5" />
                  </button>
                  <button
                    type="button"
                    disabled={matchIndices.length === 0}
                    onClick={() => jumpToMatch(1)}
                    aria-label={t("console.nextMatch")}
                    className="h-7 w-7 rounded border border-border-subtle bg-elevated text-ink-primary flex items-center justify-center disabled:opacity-40"
                  >
                    <ChevronDown className="w-3.5 h-3.5" />
                  </button>
                </div>
              )}
            </div>
          </div>

          <div className="relative">
            <div
              ref={containerRef}
              dir="ltr"
              role="log"
              aria-live="off"
              className="ltr-isolate bg-inset border border-border-subtle rounded-md p-3 font-mono text-xs h-56 overflow-y-auto space-y-0.5"
            >
              {filteredLogs.length === 0 ? (
                <div className="h-full flex items-center justify-center text-ink-muted">
                  {t("console.emptyLogs")}
                </div>
              ) : (
                filteredLogs.map((entry, idx) => (
                  <div
                    key={`${entry.id}-${idx}`}
                    ref={(el) => {
                      if (el) rowRefs.current.set(idx, el);
                      else rowRefs.current.delete(idx);
                    }}
                  >
                    <ConsoleRow entry={entry} highlighted={idx === activeLogRowIndex} />
                  </div>
                ))
              )}
              <div ref={endRef} />
            </div>

            {hasNewMessages && (
              <button
                type="button"
                onClick={() => scrollToEnd("smooth")}
                className="absolute end-4 bottom-4 px-3 py-1.5 rounded-full bg-sentinel-primary text-sentinel-onAccent text-xs font-semibold shadow-sentinelMd flex items-center gap-1.5 hover:opacity-90"
              >
                <ArrowDown className="w-3.5 h-3.5" />
                <span>{t("console.newLinesBadge", { count: unreadCount })}</span>
              </button>
            )}
          </div>
        </>
      )}
    </section>
  );
}
