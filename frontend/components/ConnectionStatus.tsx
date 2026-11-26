"use client";

import React from "react";
import { Radio, RefreshCw, WifiOff, Loader2 } from "lucide-react";
import { usePlatform } from "@/lib/platform-context";
import { useI18n } from "@/lib/i18n";

export default function ConnectionStatus() {
  const { connectionState, reconnectAttempt, reconnectStream, hunterHubHealth } = usePlatform();
  const { t } = useI18n();

  const stateConfig = {
    live: {
      containerClass:
        "border-sentinel-success/40 bg-surface/95 text-sentinel-success shadow-sentinelSm",
      dotClass: "bg-sentinel-success",
      label: t("stream.live"),
      icon: Radio,
    },
    connecting: {
      containerClass:
        "border-sentinel-primary/40 bg-surface/95 text-sentinel-primary shadow-sentinelMd",
      dotClass: "bg-sentinel-primary animate-pulse",
      label: t("stream.connecting"),
      icon: Loader2,
    },
    reconnecting: {
      containerClass:
        "border-sentinel-warning/45 bg-surface/95 text-sentinel-warning shadow-sentinelMd",
      dotClass: "bg-sentinel-warning animate-pulse",
      label:
        reconnectAttempt > 0
          ? t("stream.reconnectingAttempt", { attempt: reconnectAttempt })
          : t("stream.reconnecting"),
      icon: Loader2,
    },
    offline: {
      containerClass:
        "border-sentinel-danger/45 bg-surface/95 text-sentinel-danger shadow-sentinelMd",
      dotClass: "bg-sentinel-danger",
      label: t("stream.offline"),
      icon: WifiOff,
    },
  }[connectionState];

  const Icon = stateConfig.icon;
  const isSpinning = connectionState === "connecting" || connectionState === "reconnecting";

  return (
    <div
      data-testid="connection-status-pill"
      data-connection-state={connectionState}
      role="status"
      aria-live="polite"
      className={`fixed bottom-4 start-4 z-40 rounded-full border px-3 py-1.5 backdrop-blur-sm flex items-center gap-2 text-xs font-mono ${stateConfig.containerClass}`}
    >
      <span className={`w-2 h-2 rounded-full shrink-0 ${stateConfig.dotClass}`} aria-hidden="true" />
      <Icon className={`w-3.5 h-3.5 shrink-0 ${isSpinning ? "animate-spin" : ""}`} />
      <span>{stateConfig.label}</span>
      {hunterHubHealth.latestSeq > 0 && (
        <span className="text-[11px] text-ink-muted tabular-nums ltr-isolate">
          #{hunterHubHealth.latestSeq}
        </span>
      )}
      {connectionState !== "live" && (
        <button
          type="button"
          onClick={reconnectStream}
          aria-label={t("stream.reconnectNow")}
          title={t("stream.reconnectNow")}
          className="ms-1 min-h-[28px] px-2 rounded-full border border-current/40 bg-elevated/80 hover:bg-elevated text-[11px] font-semibold flex items-center gap-1"
        >
          <RefreshCw className="w-3 h-3" />
          <span>{t("stream.retryBtn")}</span>
        </button>
      )}
    </div>
  );
}
