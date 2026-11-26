"use client";

import React, { useMemo, useState } from "react";
import {
  Terminal,
  RefreshCw,
  Pause,
  Play,
  Trash2,
  ChevronDown,
  ChevronUp,
} from "lucide-react";
import { ConsoleLevel, usePlatform } from "@/lib/platform-context";
import { useI18n } from "@/lib/i18n";

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

export default function LiveConsole() {
  const { consoleLogs, streamPaused, setStreamPaused, clearConsoleLogs, refreshNow } =
    usePlatform();
  const { t } = useI18n();

  const [collapsed, setCollapsed] = useState<boolean>(false);
  const [levelFilter, setLevelFilter] = useState<"ALL" | ConsoleLevel>("ALL");

  const filteredLogs = useMemo(() => {
    if (levelFilter === "ALL") return consoleLogs;
    return consoleLogs.filter((entry) => entry.level === levelFilter);
  }, [consoleLogs, levelFilter]);

  return (
    <section
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
            <h2 id="live-console-heading" className="text-xs font-semibold uppercase tracking-wider font-mono">
              {t("console.title")}
            </h2>
          </button>

          {streamPaused && (
            <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-[var(--accent-warning-bg)] text-sentinel-warning border border-[var(--accent-warning)]/30">
              {t("console.pausedLabel")}
            </span>
          )}
        </div>

        <div className="flex flex-wrap items-center gap-1.5">
          <div
            role="group"
            aria-label={t("console.title")}
            className="flex items-center gap-1 bg-inset p-0.5 rounded border border-border-subtle"
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

          <button
            type="button"
            onClick={() => setStreamPaused((prev) => !prev)}
            className="h-7 px-2.5 rounded border border-border-subtle bg-elevated hover:border-border-strong text-xs text-ink-secondary hover:text-ink-primary flex items-center gap-1"
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
            onClick={clearConsoleLogs}
            className="h-7 px-2.5 rounded border border-border-subtle bg-elevated hover:border-border-strong text-xs text-ink-secondary hover:text-ink-primary flex items-center gap-1"
          >
            <Trash2 className="w-3 h-3" />
            <span>{t("console.clearBtn")}</span>
          </button>

          <button
            type="button"
            onClick={() => void refreshNow()}
            className="h-7 px-2.5 rounded border border-border-subtle bg-elevated hover:border-border-strong text-xs text-ink-secondary hover:text-ink-primary flex items-center gap-1"
          >
            <RefreshCw className="w-3 h-3" />
            <span>{t("common.refresh")}</span>
          </button>
        </div>
      </div>

      {!collapsed && (
        <div
          dir="ltr"
          className="ltr-isolate bg-inset border border-border-subtle rounded-md p-3 font-mono text-xs h-44 overflow-y-auto space-y-1"
        >
          {filteredLogs.length === 0 ? (
            <div className="h-full flex items-center justify-center text-ink-muted">
              {t("console.emptyLogs")}
            </div>
          ) : (
            filteredLogs.map((entry, idx) => (
              <div key={`${entry.id}-${idx}`} className="leading-relaxed break-all">
                <span className="text-ink-muted tabular-nums">[{entry.timestamp}]</span>{" "}
                <span className={`font-semibold ${levelStyle(entry.level)}`}>
                  [{entry.level}]
                </span>{" "}
                <span className="text-ink-secondary">[{entry.source}]</span>{" "}
                <span className="text-ink-primary">{entry.message}</span>
              </div>
            ))
          )}
        </div>
      )}
    </section>
  );
}
