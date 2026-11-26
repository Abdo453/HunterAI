"use client";

import React, { useCallback, useEffect, useState } from "react";
import { Cpu, HardDrive, MonitorSpeaker, RefreshCw, Sparkles, Server } from "lucide-react";
import { HardwareTelemetry } from "@/lib/api-types";
import { usePlatform } from "@/lib/platform-context";
import { useI18n } from "@/lib/i18n";

function GaugeBar({
  label,
  percent,
  detail,
  accentClass,
  unavailableLabel,
}: {
  label: string;
  percent: number | null;
  detail: string;
  accentClass: string;
  unavailableLabel: string;
}) {
  const valid = typeof percent === "number" && Number.isFinite(percent);
  const clamped = valid ? Math.min(100, Math.max(0, percent)) : 0;

  return (
    <div className="p-3 rounded-md bg-inset border border-border-subtle space-y-2 min-w-0">
      <div className="flex flex-wrap items-center justify-between gap-x-2 gap-y-0.5 text-xs min-w-0">
        <span className="font-semibold text-ink-secondary truncate">{label}</span>
        <span className="font-mono tabular-nums text-ink-primary ltr-isolate truncate max-w-full">
          {valid ? `${clamped.toFixed(1)}%` : unavailableLabel}
        </span>
      </div>
      <div
        role="progressbar"
        aria-label={label}
        aria-valuemin={0}
        aria-valuemax={100}
        aria-valuenow={valid ? Math.round(clamped) : undefined}
        className="w-full h-2 rounded-full bg-elevated border border-border-subtle overflow-hidden"
      >
        <div
          className={`h-full transition-[width] duration-300 ${accentClass}`}
          style={{ width: `${valid ? clamped : 0}%` }}
        />
      </div>
      <div className="text-[11px] font-mono text-ink-muted truncate ltr-isolate">{detail}</div>
    </div>
  );
}

export default function HardwareTelemetryCard({ compact = false }: { compact?: boolean }) {
  const { apiJson, hunterHubHealth } = usePlatform();
  const { t } = useI18n();

  const [telemetry, setTelemetry] = useState<HardwareTelemetry | null>(null);
  const [loading, setLoading] = useState<boolean>(false);
  const [errorMsg, setErrorMsg] = useState<string>("");

  const loadHardware = useCallback(async () => {
    setLoading(true);
    setErrorMsg("");
    const res = await apiJson<HardwareTelemetry>("/api/system/hardware");
    setLoading(false);
    if (res.ok && res.data) {
      setTelemetry(res.data);
    } else if (res.error) {
      setErrorMsg(res.error);
    }
  }, [apiJson]);

  useEffect(() => {
    if (hunterHubHealth.status === "connected") {
      void loadHardware();
    }
  }, [hunterHubHealth.status, loadHardware]);

  const cpu = telemetry?.cpu;
  const ram = telemetry?.ram;
  const gpu = telemetry?.gpu;
  const ollama = telemetry?.ollama;
  const profile = telemetry?.hardware_profile;
  const loadedModels = ollama?.loaded_models || [];
  const activeVramModel = telemetry?.vram_manager?.currently_loaded_model;

  const ramDetail =
    ram && ram.status === "ok" && ram.used_mb != null && ram.total_mb != null
      ? `${(ram.used_mb / 1024).toFixed(1)} / ${(ram.total_mb / 1024).toFixed(1)} GB`
      : t("states.unavailable");

  const cpuDetail =
    cpu && cpu.status === "ok"
      ? `${cpu.physical_cores ?? cpu.logical_cores ?? "—"}C / ${cpu.logical_cores ?? "—"}T`
      : t("states.unavailable");

  const gpuAvailable = Boolean(gpu?.available && gpu.status === "available");
  const gpuDetail = gpuAvailable
    ? `${(gpu!.vram_used_mb / 1024).toFixed(1)} / ${(gpu!.vram_total_mb / 1024).toFixed(1)} GB · ${gpu!.gpus[0]?.name || gpu!.source}`
    : t("hardware.cpuOnlyHost");

  return (
    <section
      data-testid="hardware-telemetry-card"
      aria-labelledby="hardware-telemetry-heading"
      className="sentinel-surface p-4 space-y-3"
    >
      <div className="flex flex-wrap items-center justify-between gap-2 pb-2 border-b border-border-subtle">
        <div className="flex items-center gap-2 min-w-0">
          <Cpu className="w-4 h-4 text-sentinel-primary shrink-0" />
          <h2 id="hardware-telemetry-heading" className="text-sm font-semibold text-ink-primary truncate">
            {t("hardware.title")}
          </h2>
          {profile?.active && (
            <span className="px-2 py-0.5 rounded-full text-[10px] font-mono bg-sentinel-ai/15 text-sentinel-ai border border-sentinel-ai/35 ltr-isolate">
              {profile.active}
            </span>
          )}
        </div>

        <div className="flex items-center gap-2">
          <span
            data-testid="hardware-gpu-badge"
            className={`px-2 py-0.5 rounded text-[11px] font-mono border ${
              gpuAvailable
                ? "bg-sentinel-success/15 text-sentinel-success border-sentinel-success/35"
                : "bg-elevated text-ink-muted border-border-subtle"
            }`}
          >
            {gpuAvailable ? t("hardware.gpuAvailable") : t("states.unavailable")}
          </span>
          <button
            type="button"
            onClick={() => void loadHardware()}
            disabled={loading}
            aria-label={t("common.refresh")}
            className="min-h-[32px] px-2.5 rounded border border-border-subtle bg-elevated hover:border-border-strong text-xs text-ink-primary flex items-center gap-1 disabled:opacity-50"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? "animate-spin" : ""}`} />
            <span className="hidden sm:inline">{t("common.refresh")}</span>
          </button>
        </div>
      </div>

      {errorMsg && (
        <div
          role="alert"
          className="px-3 py-2 rounded bg-sentinel-danger/15 border border-sentinel-danger/40 text-sentinel-danger text-xs"
        >
          {errorMsg}
        </div>
      )}

      <div className={`grid grid-cols-1 ${compact ? "sm:grid-cols-3" : "md:grid-cols-3"} gap-3`}>
        <GaugeBar
          label={t("hardware.cpuLabel")}
          percent={cpu?.status === "ok" ? cpu.percent : null}
          detail={cpuDetail}
          accentClass="bg-sentinel-primary"
          unavailableLabel={t("states.unavailable")}
        />
        <GaugeBar
          label={t("hardware.ramLabel")}
          percent={ram?.status === "ok" ? ram.percent : null}
          detail={ramDetail}
          accentClass="bg-sentinel-success"
          unavailableLabel={t("states.unavailable")}
        />
        <GaugeBar
          label={t("hardware.vramLabel")}
          percent={gpuAvailable ? gpu?.vram_used_pct ?? null : null}
          detail={gpuDetail}
          accentClass={gpuAvailable ? "bg-sentinel-ai" : "bg-border-subtle"}
          unavailableLabel={t("states.unavailable")}
        />
      </div>

      {/* Ollama / VRAM Loaded Models */}
      <div className="p-3 rounded-md bg-inset border border-border-subtle space-y-2 text-xs">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <div className="flex items-center gap-1.5 text-ink-secondary font-semibold">
            <Server className="w-3.5 h-3.5 text-sentinel-primary" />
            <span>{t("hardware.ollamaModels")}</span>
          </div>
          <span
            className={`px-2 py-0.5 rounded font-mono text-[10px] border ${
              ollama?.status === "online"
                ? "bg-sentinel-success/15 text-sentinel-success border-sentinel-success/35"
                : "bg-elevated text-ink-muted border-border-subtle"
            }`}
          >
            {ollama?.status ? ollama.status.toUpperCase() : t("states.offline")}
          </span>
        </div>

        {loadedModels.length === 0 ? (
          <div className="flex items-center justify-between gap-2 text-ink-muted text-[11px]">
            <span>{t("hardware.noLoadedModels")}</span>
            {activeVramModel && (
              <span className="font-mono text-sentinel-ai ltr-isolate">{activeVramModel}</span>
            )}
          </div>
        ) : (
          <div className="flex flex-wrap gap-1.5">
            {loadedModels.map((m) => (
              <span
                key={m.name}
                className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded bg-elevated border border-border-subtle font-mono text-[11px] text-ink-primary ltr-isolate"
              >
                <Sparkles className="w-3 h-3 text-sentinel-ai shrink-0" />
                <span>{m.name}</span>
                <span className="text-ink-muted tabular-nums">
                  {Math.round(m.size_vram_mb || m.size_mb)} MB
                </span>
              </span>
            ))}
          </div>
        )}

        {!compact && profile && (
          <div className="pt-2 border-t border-border-subtle flex flex-wrap items-center gap-3 text-[11px] font-mono text-ink-muted">
            <span className="flex items-center gap-1">
              <HardDrive className="w-3 h-3 text-sentinel-primary" />
              {t("hardware.contextWindow")}: {profile.default_num_ctx ?? "—"}
            </span>
            <span className="flex items-center gap-1">
              <MonitorSpeaker className="w-3 h-3 text-sentinel-warning" />
              {t("hardware.keepAlive")}: {profile.keep_alive_seconds ?? 0}s
            </span>
            {telemetry?.platform?.system && (
              <span className="ltr-isolate">
                {telemetry.platform.system} {telemetry.platform.machine}
              </span>
            )}
          </div>
        )}
      </div>
    </section>
  );
}
