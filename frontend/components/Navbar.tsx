"use client";

import React, { useEffect, useMemo, useRef, useState } from "react";
import { useRouter } from "next/navigation";
import {
  Play,
  Loader2,
  Database,
  Sun,
  Moon,
  Languages,
  Bot,
  Menu,
  X,
  AlertCircle,
  Radio,
  Search,
  Activity,
  ShieldCheck,
  Bookmark,
  ChevronDown,
  Globe,
  Server,
} from "lucide-react";
import {
  ServiceConnectivity,
  usePlatform,
  validateScanTarget,
} from "@/lib/platform-context";
import {
  TARGET_PRESETS,
  TargetPreset,
  getPresetCategoryBadgeClasses,
  getPresetDescription,
} from "@/lib/target-presets";
import { useTheme } from "@/lib/theme";
import { useI18n } from "@/lib/i18n";

function formatSyncTime(ts: number | null, neverLabel: string): string {
  if (!ts) return neverLabel;
  return new Date(ts).toLocaleTimeString("en-GB", { hour12: false });
}

function getStatusBadgeStyle(status: ServiceConnectivity): {
  dotClass: string;
  pillClass: string;
} {
  switch (status) {
    case "connected":
      return {
        dotClass: "bg-[var(--accent-success)]",
        pillClass:
          "border-[var(--accent-success)]/30 bg-[var(--accent-success-bg)] text-[var(--accent-success)]",
      };
    case "degraded":
      return {
        dotClass: "bg-[var(--accent-warning)]",
        pillClass:
          "border-[var(--accent-warning)]/30 bg-[var(--accent-warning-bg)] text-[var(--accent-warning)]",
      };
    case "checking":
      return {
        dotClass: "bg-[var(--accent-primary)]",
        pillClass:
          "border-[var(--accent-primary)]/30 bg-[var(--accent-primary-bg)] text-[var(--accent-primary)]",
      };
    default:
      return {
        dotClass: "bg-[var(--accent-danger)]",
        pillClass:
          "border-[var(--accent-danger)]/30 bg-[var(--accent-danger-bg)] text-[var(--accent-danger)]",
      };
  }
}

interface NavbarProps {
  mobileNavOpen?: boolean;
  onToggleMobileNav?: () => void;
}

export default function Navbar({ mobileNavOpen = false, onToggleMobileNav }: NavbarProps) {
  const router = useRouter();
  const {
    engagements,
    selectedEngagementId,
    selectedEngagement,
    selectEngagement,
    targetDomain,
    isScanning,
    launchScan,
    runs,
    activeRunId,
    goCoreHealth,
    hunterHubHealth,
    pendingApprovalsCount,
    copilotOpen,
    setCopilotOpen,
    setCommandPaletteOpen,
  } = usePlatform();

  const { theme, toggleTheme } = useTheme();
  const { lang, toggleLang, t } = useI18n();

  const [targetInput, setTargetInput] = useState<string>(targetDomain || "");
  const [validationError, setValidationError] = useState<string>("");
  const [presetsOpen, setPresetsOpen] = useState<boolean>(false);

  const presetsContainerRef = useRef<HTMLDivElement>(null);
  const presetsBtnRef = useRef<HTMLButtonElement>(null);
  const targetInputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    if (selectedEngagement?.target) {
      setTargetInput(selectedEngagement.target);
      setValidationError("");
    }
  }, [selectedEngagement]);

  useEffect(() => {
    if (!presetsOpen) return;
    const onPointerDown = (ev: MouseEvent) => {
      if (
        presetsContainerRef.current &&
        !presetsContainerRef.current.contains(ev.target as Node)
      ) {
        setPresetsOpen(false);
      }
    };
    const onKeyDown = (ev: KeyboardEvent) => {
      if (ev.key === "Escape") {
        setPresetsOpen(false);
        presetsBtnRef.current?.focus();
      }
    };
    document.addEventListener("mousedown", onPointerDown);
    window.addEventListener("keydown", onKeyDown);
    return () => {
      document.removeEventListener("mousedown", onPointerDown);
      window.removeEventListener("keydown", onKeyDown);
    };
  }, [presetsOpen]);

  const handleSelectPreset = (preset: TargetPreset) => {
    setTargetInput(preset.target);
    setValidationError("");
    setPresetsOpen(false);
    targetInputRef.current?.focus();
  };

  useEffect(() => {
    const onKeyDown = (ev: KeyboardEvent) => {
      if ((ev.ctrlKey || ev.metaKey) && ev.key.toLowerCase() === "j") {
        ev.preventDefault();
        setCopilotOpen((prev) => !prev);
      }
    };
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, [setCopilotOpen]);

  const activeRun = useMemo(() => {
    const isLive = (r: { status?: string }) =>
      ["running", "paused", "pending"].includes((r.status || "").toLowerCase());
    if (activeRunId) {
      const m = runs.find((r) => r.run_id === activeRunId && isLive(r));
      if (m) return m;
    }
    return runs.find(isLive) || null;
  }, [runs, activeRunId]);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setValidationError("");

    const check = validateScanTarget(targetInput);
    if (!check.valid) {
      const msgKey =
        check.reason === "empty"
          ? "nav.scopeInvalidEmpty"
          : "nav.scopeFormatHint";
      setValidationError(t(msgKey));
      return;
    }

    const res = await launchScan(check.normalizedTarget);
    if (!res.ok && res.error) {
      setValidationError(res.error);
    }
  };

  const goStyle = getStatusBadgeStyle(goCoreHealth.status);
  const hubStyle = getStatusBadgeStyle(hunterHubHealth.status);

  const goStatusLabel =
    goCoreHealth.status === "connected"
      ? t("status.connected")
      : goCoreHealth.status === "degraded"
        ? t("status.degraded")
        : goCoreHealth.status === "checking"
          ? t("status.checking")
          : t("status.offline");

  const hubStatusLabel =
    hunterHubHealth.status === "connected"
      ? t("status.connected")
      : hunterHubHealth.status === "checking"
        ? t("status.checking")
        : t("status.offline");

  return (
    <header className="sticky top-0 z-30 border-b border-border-subtle bg-surface/95 backdrop-blur-sm">
      <div className="px-3 sm:px-5 py-2.5 flex flex-wrap items-center justify-between gap-2.5">
        {/* Mobile Sidebar Toggle + Brand Pill on <lg */}
        <div className="flex items-center gap-2 lg:hidden">
          <button
            type="button"
            onClick={onToggleMobileNav}
            aria-expanded={mobileNavOpen}
            aria-label={t("nav.menuBtn")}
            className="min-h-[44px] min-w-[44px] rounded-md border border-border-subtle bg-elevated text-ink-primary flex items-center justify-center"
          >
            {mobileNavOpen ? <X className="w-5 h-5" /> : <Menu className="w-5 h-5" />}
          </button>
          <span className="font-bold text-sm text-ink-primary">{t("brand.name")}</span>
        </div>

        {/* Workspace Selector + Target Launcher */}
        <div
          ref={presetsContainerRef}
          className="relative flex-1 min-w-[240px] max-w-2xl flex flex-col gap-1 order-3 lg:order-1 w-full lg:w-auto"
        >
          <form onSubmit={handleSubmit} className="flex flex-wrap sm:flex-nowrap items-center gap-2">
            <label htmlFor="engagement-selector" className="sr-only">
              {t("nav.engagementLabel")}
            </label>
            <select
              id="engagement-selector"
              value={selectedEngagementId}
              onChange={(e) => {
                void selectEngagement(e.target.value);
              }}
              aria-label={t("nav.engagementLabel")}
              className="min-h-[44px] lg:min-h-0 lg:h-9 px-2.5 rounded-md bg-elevated border border-border-subtle text-xs text-ink-primary max-w-[165px] sm:max-w-[190px] truncate shrink-0"
            >
              <option value="">{t("nav.allEngagements")}</option>
              {engagements.map((eng, idx) => (
                <option key={`${eng.id}-${idx}`} value={eng.id}>
                  {eng.name} ({eng.source === "artex_go" ? "Go" : "Hub"})
                </option>
              ))}
            </select>

            <div className="relative flex-1 min-w-[160px]">
              <label htmlFor="scan-target-input" className="sr-only">
                {t("nav.targetPlaceholder", "Target domain (e.g. example.com)")}
              </label>
              <input
                ref={targetInputRef}
                id="scan-target-input"
                type="text"
                dir="ltr"
                list="target-example-presets"
                placeholder={t("nav.targetPlaceholder", "Target domain (e.g. example.com)")}
                value={targetInput}
                onChange={(e) => {
                  setTargetInput(e.target.value);
                  if (validationError) setValidationError("");
                }}
                aria-invalid={Boolean(validationError)}
                className="ltr-isolate w-full min-h-[44px] lg:min-h-0 lg:h-9 px-3 rounded-md bg-inset border border-border-subtle text-sm font-mono text-ink-primary placeholder:text-ink-muted focus:border-sentinel-primary transition-colors"
              />
              <datalist id="target-example-presets">
                {TARGET_PRESETS.map((preset) => (
                  <option key={preset.id} value={preset.target}>
                    {`${preset.label} — ${getPresetDescription(preset, lang)}`}
                  </option>
                ))}
              </datalist>
            </div>

            <button
              ref={presetsBtnRef}
              type="button"
              data-testid="navbar-target-presets-btn"
              onClick={() => setPresetsOpen((prev) => !prev)}
              aria-expanded={presetsOpen}
              aria-controls="navbar-target-presets-popover"
              aria-label={t("nav.presetsAriaLabel")}
              className={`min-h-[44px] lg:min-h-0 lg:h-9 px-2.5 rounded-md border text-xs font-medium flex items-center gap-1.5 transition-colors shrink-0 ${
                presetsOpen
                  ? "border-sentinel-primary bg-[var(--accent-primary-bg)] text-sentinel-primary"
                  : "border-border-subtle bg-elevated hover:border-border-strong text-ink-primary"
              }`}
            >
              <Bookmark className="w-3.5 h-3.5 text-sentinel-primary shrink-0" />
              <span>{t("nav.presetsBtn")}</span>
              <ChevronDown
                className={`w-3.5 h-3.5 text-ink-muted transition-transform ${
                  presetsOpen ? "rotate-180" : ""
                }`}
              />
            </button>

            <button
              type="submit"
              disabled={isScanning || !targetInput.trim()}
              className="min-h-[44px] lg:min-h-0 lg:h-9 px-3.5 rounded-md bg-sentinel-primary text-sentinel-onAccent text-xs font-semibold flex items-center gap-1.5 hover:opacity-90 disabled:opacity-50 disabled:cursor-not-allowed transition-opacity shrink-0"
            >
              {isScanning ? (
                <>
                  <Loader2 className="w-3.5 h-3.5 animate-spin" />
                  <span>{t("nav.launching")}</span>
                </>
              ) : (
                <>
                  <Play className="w-3.5 h-3.5" />
                  <span>{t("nav.launchMission")}</span>
                </>
              )}
            </button>
          </form>

          {presetsOpen && (
            <div
              id="navbar-target-presets-popover"
              role="region"
              aria-label={t("nav.presetsTitle")}
              className="absolute top-full start-0 end-0 sm:end-auto sm:w-[460px] max-w-[calc(100vw-1.5rem)] mt-1.5 z-50 rounded-lg border border-border-strong bg-surface shadow-sentinelMd p-3 space-y-2.5 max-h-[70vh] overflow-y-auto"
            >
              <div className="flex items-center justify-between gap-2 pb-2 border-b border-border-subtle">
                <div className="min-w-0">
                  <div className="text-xs font-semibold text-ink-primary truncate">
                    {t("nav.presetsTitle")}
                  </div>
                  <div className="text-[11px] text-ink-muted truncate">
                    {t("nav.presetsSubtitle")}
                  </div>
                </div>
                <button
                  type="button"
                  onClick={() => setPresetsOpen(false)}
                  aria-label={t("common.close")}
                  className="h-7 w-7 rounded border border-border-subtle bg-elevated hover:border-border-strong text-ink-muted hover:text-ink-primary flex items-center justify-center shrink-0"
                >
                  <X className="w-3.5 h-3.5" />
                </button>
              </div>

              {(["public_demo", "local_lab"] as const).map((categoryKey) => {
                const items = TARGET_PRESETS.filter((p) => p.category === categoryKey);
                const isPublic = categoryKey === "public_demo";
                return (
                  <div key={categoryKey} className="space-y-1.5">
                    <div className="flex items-center justify-between gap-2 text-[11px] font-semibold text-ink-secondary px-0.5">
                      <span className="flex items-center gap-1.5">
                        {isPublic ? (
                          <Globe className="w-3.5 h-3.5 text-sentinel-primary shrink-0" />
                        ) : (
                          <Server className="w-3.5 h-3.5 text-sentinel-warning shrink-0" />
                        )}
                        <span>
                          {isPublic ? t("targets.presetGroupPublic") : t("targets.presetGroupLocal")}
                        </span>
                      </span>
                      <span className="font-mono text-[10px] text-ink-muted tabular-nums">
                        {items.length}
                      </span>
                    </div>

                    <div className="grid grid-cols-1 gap-1.5">
                      {items.map((preset) => {
                        const isActive = targetInput.trim() === preset.target;
                        return (
                          <button
                            key={preset.id}
                            type="button"
                            onClick={() => handleSelectPreset(preset)}
                            className={`w-full text-start p-2 rounded-md border transition-colors flex flex-col gap-1 ${
                              isActive
                                ? "border-sentinel-primary bg-[var(--accent-primary-bg)]"
                                : "border-border-subtle bg-elevated/60 hover:bg-elevated hover:border-border-strong"
                            }`}
                          >
                            <div className="flex items-center justify-between gap-2 min-w-0">
                              <span className="text-xs font-semibold text-ink-primary truncate">
                                {preset.label}
                              </span>
                              <span
                                className={`px-1.5 py-0.5 rounded text-[10px] font-mono border shrink-0 ${getPresetCategoryBadgeClasses(
                                  preset.category
                                )}`}
                              >
                                {isPublic
                                  ? t("targets.presetBadgePublic")
                                  : t("targets.presetBadgeLab")}
                              </span>
                            </div>
                            <span className="ltr-isolate font-mono text-[11px] text-sentinel-primary truncate block">
                              {preset.target}
                            </span>
                            <span className="text-[11px] text-ink-muted line-clamp-1">
                              {getPresetDescription(preset, lang)}
                            </span>
                          </button>
                        );
                      })}
                    </div>
                  </div>
                );
              })}
            </div>
          )}

          {validationError && (
            <div
              role="alert"
              className="flex items-center gap-1.5 text-xs text-sentinel-danger px-1"
            >
              <AlertCircle className="w-3.5 h-3.5 shrink-0" />
              <span>{validationError}</span>
            </div>
          )}
        </div>

        {/* Status Pills, Command Palette, Approvals, Theme/Lang, Copilot */}
        <div className="flex items-center gap-1.5 order-2">
          {activeRun && (
            <button
              type="button"
              onClick={() => router.push("/")}
              title={`${activeRun.kind} · ${activeRun.target}`}
              className="hidden sm:flex items-center gap-1.5 h-9 px-2.5 rounded-full border border-[var(--accent-primary)]/35 bg-[var(--accent-primary-bg)] text-sentinel-primary text-xs font-mono"
            >
              <Activity className="w-3.5 h-3.5 animate-pulse" />
              <span className="truncate max-w-[130px] ltr-isolate">
                {activeRun.kind}: {activeRun.current_phase || activeRun.status}
              </span>
            </button>
          )}

          <div className="hidden 2xl:flex items-center gap-1.5 text-[11px] font-mono">
            <div
              title={`${t("nav.goCore")} · DB: ${goCoreHealth.database} · ${t("nav.lastSynced")}: ${formatSyncTime(goCoreHealth.lastSyncedAt, t("status.never"))}`}
              className={`flex items-center gap-1.5 px-2.5 py-1 rounded-full border ${goStyle.pillClass}`}
            >
              <span className={`w-2 h-2 rounded-full ${goStyle.dotClass}`} />
              <Database className="w-3 h-3" />
              <span>{goStatusLabel}</span>
            </div>

            <div
              title={`${t("nav.hunterHub")} · ${t("nav.lastSynced")}: ${formatSyncTime(hunterHubHealth.lastSyncedAt, t("status.never"))}`}
              className={`flex items-center gap-1.5 px-2.5 py-1 rounded-full border ${hubStyle.pillClass}`}
            >
              <span className={`w-2 h-2 rounded-full ${hubStyle.dotClass}`} />
              <Radio className="w-3 h-3" />
              <span>{hubStatusLabel}</span>
            </div>
          </div>

          <button
            type="button"
            onClick={() => setCommandPaletteOpen(true)}
            aria-label={t("nav.commandPalette")}
            title={t("nav.commandPalette")}
            className="min-h-[44px] min-w-[44px] lg:min-h-0 lg:min-w-0 lg:h-9 px-2.5 rounded-md border border-border-subtle bg-elevated hover:border-border-strong text-xs text-ink-secondary hover:text-ink-primary flex items-center justify-center gap-1.5"
          >
            <Search className="w-3.5 h-3.5 text-sentinel-primary" />
            <span className="hidden xl:inline font-mono text-[11px]">Ctrl+K</span>
          </button>

          <button
            type="button"
            onClick={() => {
              router.push("/");
              window.setTimeout(() => {
                document.getElementById("approvals-panel")?.scrollIntoView({ behavior: "smooth", block: "nearest" });
              }, 120);
            }}
            aria-label={t("approvals.title")}
            title={t("approvals.title")}
            className="min-h-[44px] min-w-[44px] lg:min-h-0 lg:min-w-0 lg:h-9 px-2.5 rounded-md border border-border-subtle bg-elevated hover:border-border-strong text-xs text-ink-primary flex items-center justify-center gap-1.5"
          >
            <ShieldCheck
              className={`w-4 h-4 ${
                pendingApprovalsCount > 0 ? "text-sentinel-warning" : "text-ink-muted"
              }`}
            />
            {pendingApprovalsCount > 0 && (
              <span className="px-1.5 py-0.5 rounded-full text-[10px] font-mono tabular-nums bg-[var(--accent-warning-bg)] text-sentinel-warning border border-[var(--accent-warning)]/30">
                {pendingApprovalsCount}
              </span>
            )}
          </button>

          <button
            type="button"
            onClick={toggleLang}
            aria-label={t("topbar.languageToggle")}
            title={t("topbar.languageToggle")}
            className="min-h-[44px] min-w-[44px] lg:min-h-0 lg:min-w-0 lg:h-9 px-2.5 rounded-md border border-border-subtle bg-elevated hover:border-border-strong text-xs font-mono text-ink-primary flex items-center justify-center gap-1.5"
          >
            <Languages className="w-3.5 h-3.5 text-sentinel-primary" />
            <span>{lang === "ar" ? "EN" : "AR"}</span>
          </button>

          <button
            type="button"
            onClick={toggleTheme}
            aria-label={t("topbar.themeToggle")}
            title={t("topbar.themeToggle")}
            className="min-h-[44px] min-w-[44px] lg:min-h-0 lg:min-w-0 lg:h-9 lg:w-9 rounded-md border border-border-subtle bg-elevated hover:border-border-strong text-ink-primary flex items-center justify-center"
          >
            {theme === "dark" ? (
              <Sun className="w-4 h-4 text-sentinel-warning" />
            ) : (
              <Moon className="w-4 h-4 text-sentinel-primary" />
            )}
          </button>

          <button
            type="button"
            onClick={() => setCopilotOpen((prev) => !prev)}
            aria-expanded={copilotOpen}
            aria-label={t("nav.copilotBtn")}
            title="Copilot (Ctrl+J)"
            className={`min-h-[44px] lg:min-h-0 lg:h-9 px-3 rounded-md border text-xs font-semibold flex items-center gap-1.5 transition-colors ${
              copilotOpen
                ? "border-sentinel-ai bg-[var(--accent-ai-bg)] text-sentinel-ai"
                : "border-border-subtle bg-elevated text-ink-primary hover:border-border-strong"
            }`}
          >
            <Bot className="w-4 h-4 text-sentinel-ai" />
            <span className="hidden sm:inline">{t("nav.copilotBtn")}</span>
          </button>
        </div>
      </div>
    </header>
  );
}
