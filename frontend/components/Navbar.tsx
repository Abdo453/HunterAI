"use client";

import React, { useEffect, useState } from "react";
import {
  Shield,
  Play,
  Loader2,
  Database,
  Activity,
  ExternalLink,
  Sun,
  Moon,
  Languages,
  Bot,
  Menu,
  X,
  AlertCircle,
  Radio,
} from "lucide-react";
import {
  HUNTER_API_BASE,
  ServiceConnectivity,
  usePlatform,
  validateScanTarget,
} from "@/lib/platform-context";
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

export default function Navbar() {
  const {
    engagements,
    selectedEngagementId,
    selectedEngagement,
    selectEngagement,
    targetDomain,
    isScanning,
    launchScan,
    goCoreHealth,
    hunterHubHealth,
    pendingApprovalsCount,
    copilotOpen,
    setCopilotOpen,
  } = usePlatform();

  const { theme, toggleTheme } = useTheme();
  const { lang, toggleLang, t } = useI18n();

  const [targetInput, setTargetInput] = useState<string>(targetDomain || "");
  const [validationError, setValidationError] = useState<string>("");
  const [mobileMenuOpen, setMobileMenuOpen] = useState<boolean>(false);

  useEffect(() => {
    if (selectedEngagement?.target) {
      setTargetInput(selectedEngagement.target);
      setValidationError("");
    }
  }, [selectedEngagement]);

  useEffect(() => {
    const onKeyDown = (ev: KeyboardEvent) => {
      if ((ev.ctrlKey || ev.metaKey) && ev.key.toLowerCase() === "j") {
        ev.preventDefault();
        setCopilotOpen((prev) => !prev);
      } else if (ev.key === "Escape" && mobileMenuOpen) {
        setMobileMenuOpen(false);
      }
    };
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, [mobileMenuOpen, setCopilotOpen]);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setValidationError("");

    const check = validateScanTarget(targetInput, selectedEngagement);
    if (!check.valid) {
      const msgKey =
        check.reason === "empty"
          ? "nav.scopeInvalidEmpty"
          : check.reason === "blocked_local"
            ? "nav.scopeInvalidLocal"
            : check.reason === "out_of_scope"
              ? "nav.scopeOutOfScope"
              : check.reason === "not_in_scope"
                ? "nav.scopeNotInScope"
                : "nav.scopeFormatHint";
      setValidationError(t(msgKey));
      return;
    }

    const res = await launchScan(check.normalizedTarget);
    if (!res.ok && res.error) {
      setValidationError(res.error);
    }
  };

  const controlCenterUrl = `${HUNTER_API_BASE}/?theme=${encodeURIComponent(theme)}&lang=${encodeURIComponent(lang)}`;
  const opencodeUrl = `${HUNTER_API_BASE}/opencode?theme=${encodeURIComponent(theme)}&lang=${encodeURIComponent(lang)}`;

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
    <header className="sticky top-0 z-40 border-b border-border-subtle bg-surface/95 backdrop-blur-sm">
      <div className="max-w-[1440px] mx-auto px-4 sm:px-6 py-3 flex flex-wrap items-center justify-between gap-3">
        {/* Brand */}
        <div className="flex items-center gap-3 min-w-0">
          <div className="w-9 h-9 rounded-md bg-[var(--accent-primary-bg)] border border-[var(--accent-primary)]/30 flex items-center justify-center text-sentinel-primary shrink-0">
            <Shield className="w-5 h-5" />
          </div>
          <div className="min-w-0">
            <div className="flex items-center gap-2">
              <h1 className="m-0 font-bold text-base text-ink-primary tracking-tight">
                {t("brand.name")}
              </h1>
              <span className="text-[11px] font-mono px-1.5 py-0.5 rounded bg-elevated text-ink-secondary border border-border-subtle">
                {t("brand.engineTag")}
              </span>
            </div>
            <p className="text-xs text-ink-muted truncate hidden sm:block">
              {t("brand.subtitle")}
            </p>
          </div>
        </div>

        {/* Engagement Selector + Target Launcher */}
        <div className="flex-1 min-w-[260px] max-w-2xl flex flex-col gap-1 order-3 lg:order-2 w-full lg:w-auto">
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
              className="h-9 px-2.5 rounded-md bg-elevated border border-border-subtle text-xs text-ink-primary max-w-[190px] truncate shrink-0"
            >
              <option value="">{t("nav.allEngagements")}</option>
              {engagements.map((eng) => (
                <option key={eng.id} value={eng.id}>
                  {eng.name} ({eng.source === "artex_go" ? "Go" : "Hub"})
                </option>
              ))}
            </select>

            <div className="relative flex-1 min-w-[180px]">
              <label htmlFor="scan-target-input" className="sr-only">
                {t("nav.targetPlaceholder", "Target domain (e.g. example.com)")}
              </label>
              <input
                id="scan-target-input"
                type="text"
                dir="ltr"
                placeholder={t("nav.targetPlaceholder", "Target domain (e.g. example.com)")}
                value={targetInput}
                onChange={(e) => {
                  setTargetInput(e.target.value);
                  if (validationError) setValidationError("");
                }}
                aria-invalid={Boolean(validationError)}
                className="ltr-isolate w-full h-9 px-3 rounded-md bg-inset border border-border-subtle text-sm font-mono text-ink-primary placeholder:text-ink-muted focus:border-sentinel-primary transition-colors"
              />
            </div>

            <button
              type="submit"
              disabled={isScanning || !targetInput.trim()}
              className="h-9 px-3.5 rounded-md bg-sentinel-primary text-sentinel-onAccent text-xs font-semibold flex items-center gap-1.5 hover:opacity-90 disabled:opacity-50 disabled:cursor-not-allowed transition-opacity shrink-0"
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

        {/* Live Telemetry Badges + Controls */}
        <div className="flex items-center gap-2 order-2 lg:order-3">
          {/* Truthful Go Core + FastAPI Hub status pills */}
          <div className="hidden xl:flex items-center gap-2 text-xs font-mono">
            <div
              title={`${t("nav.goCore")} · DB: ${goCoreHealth.database} · ${t("nav.lastSynced")}: ${formatSyncTime(goCoreHealth.lastSyncedAt, t("status.never"))}`}
              className={`flex items-center gap-1.5 px-2.5 py-1 rounded-full border ${goStyle.pillClass}`}
            >
              <span className={`w-2 h-2 rounded-full ${goStyle.dotClass}`} />
              <Database className="w-3 h-3" />
              <span>
                {t("nav.goCore")}: {goStatusLabel}
              </span>
            </div>

            <div
              title={`${t("nav.hunterHub")} · ${t("nav.lastSynced")}: ${formatSyncTime(hunterHubHealth.lastSyncedAt, t("status.never"))}`}
              className={`flex items-center gap-1.5 px-2.5 py-1 rounded-full border ${hubStyle.pillClass}`}
            >
              <span className={`w-2 h-2 rounded-full ${hubStyle.dotClass}`} />
              <Radio className="w-3 h-3" />
              <span>
                {t("nav.hunterHub")}: {hubStatusLabel}
              </span>
            </div>
          </div>

          {/* Desktop External Links & Toggles */}
          <div className="hidden md:flex items-center gap-1.5">
            <a
              href={controlCenterUrl}
              target="_blank"
              rel="noopener noreferrer"
              className="h-9 px-2.5 rounded-md border border-border-subtle bg-elevated hover:border-border-strong text-xs text-ink-secondary hover:text-ink-primary flex items-center gap-1.5 transition-colors"
            >
              <Activity className="w-3.5 h-3.5 text-sentinel-primary" />
              <span>{t("nav.controlCenter")}</span>
              <ExternalLink className="w-3 h-3 opacity-70" />
            </a>

            <a
              href={opencodeUrl}
              target="_blank"
              rel="noopener noreferrer"
              className="h-9 px-2.5 rounded-md border border-border-subtle bg-elevated hover:border-border-strong text-xs text-ink-secondary hover:text-ink-primary flex items-center gap-1.5 transition-colors"
            >
              <span>{t("nav.opencodeIde")}</span>
              <ExternalLink className="w-3 h-3 opacity-70" />
            </a>

            <button
              type="button"
              onClick={toggleLang}
              aria-label={t("topbar.languageToggle")}
              title={t("topbar.languageToggle")}
              className="h-9 px-2.5 rounded-md border border-border-subtle bg-elevated hover:border-border-strong text-xs font-mono text-ink-primary flex items-center gap-1.5 transition-colors"
            >
              <Languages className="w-3.5 h-3.5 text-sentinel-primary" />
              <span>{lang === "ar" ? "EN" : "AR"}</span>
            </button>

            <button
              type="button"
              onClick={toggleTheme}
              aria-label={t("topbar.themeToggle")}
              title={t("topbar.themeToggle")}
              className="h-9 w-9 rounded-md border border-border-subtle bg-elevated hover:border-border-strong text-ink-primary flex items-center justify-center transition-colors"
            >
              {theme === "dark" ? (
                <Sun className="w-4 h-4 text-sentinel-warning" />
              ) : (
                <Moon className="w-4 h-4 text-sentinel-primary" />
              )}
            </button>
          </div>

          {/* Copilot Toggle */}
          <button
            type="button"
            onClick={() => setCopilotOpen((prev) => !prev)}
            aria-expanded={copilotOpen}
            aria-label={t("nav.copilotBtn")}
            className={`h-9 px-3 rounded-md border text-xs font-semibold flex items-center gap-1.5 transition-colors ${
              copilotOpen
                ? "border-sentinel-ai bg-[var(--accent-ai-bg)] text-sentinel-ai"
                : "border-border-subtle bg-elevated text-ink-primary hover:border-border-strong"
            }`}
          >
            <Bot className="w-4 h-4 text-sentinel-ai" />
            <span className="hidden sm:inline">{t("nav.copilotBtn")}</span>
            {pendingApprovalsCount > 0 && (
              <span className="px-1.5 py-0.2 rounded-full text-[10px] font-mono tabular-nums bg-[var(--accent-warning-bg)] text-sentinel-warning border border-[var(--accent-warning)]/30">
                {pendingApprovalsCount}
              </span>
            )}
          </button>

          {/* Mobile Menu Trigger */}
          <button
            type="button"
            onClick={() => setMobileMenuOpen((prev) => !prev)}
            aria-expanded={mobileMenuOpen}
            aria-label={t("nav.menuBtn")}
            className="md:hidden h-9 w-9 rounded-md border border-border-subtle bg-elevated text-ink-primary flex items-center justify-center"
          >
            {mobileMenuOpen ? <X className="w-4 h-4" /> : <Menu className="w-4 h-4" />}
          </button>
        </div>
      </div>

      {/* Responsive Mobile Drawer */}
      {mobileMenuOpen && (
        <div className="md:hidden border-t border-border-subtle bg-surface px-4 py-3 space-y-3">
          <div className="flex flex-wrap gap-2 text-xs font-mono">
            <div className={`flex items-center gap-1.5 px-2.5 py-1 rounded-full border ${goStyle.pillClass}`}>
              <span className={`w-2 h-2 rounded-full ${goStyle.dotClass}`} />
              <span>
                {t("nav.goCore")}: {goStatusLabel}
              </span>
            </div>
            <div className={`flex items-center gap-1.5 px-2.5 py-1 rounded-full border ${hubStyle.pillClass}`}>
              <span className={`w-2 h-2 rounded-full ${hubStyle.dotClass}`} />
              <span>
                {t("nav.hunterHub")}: {hubStatusLabel}
              </span>
            </div>
          </div>

          <div className="text-xs text-ink-muted font-mono ltr-isolate">
            {t("nav.lastSynced")}: {formatSyncTime(goCoreHealth.lastSyncedAt ?? hunterHubHealth.lastSyncedAt, t("status.never"))}
          </div>

          <div className="flex flex-wrap items-center gap-2">
            <a
              href={controlCenterUrl}
              target="_blank"
              rel="noopener noreferrer"
              className="h-9 px-3 rounded-md border border-border-subtle bg-elevated text-xs text-ink-primary flex items-center gap-1.5"
            >
              <Activity className="w-3.5 h-3.5 text-sentinel-primary" />
              <span>{t("nav.controlCenter")}</span>
              <ExternalLink className="w-3 h-3" />
            </a>

            <a
              href={opencodeUrl}
              target="_blank"
              rel="noopener noreferrer"
              className="h-9 px-3 rounded-md border border-border-subtle bg-elevated text-xs text-ink-primary flex items-center gap-1.5"
            >
              <span>{t("nav.opencodeIde")}</span>
              <ExternalLink className="w-3 h-3" />
            </a>

            <button
              type="button"
              onClick={toggleLang}
              className="h-9 px-3 rounded-md border border-border-subtle bg-elevated text-xs font-mono text-ink-primary flex items-center gap-1.5"
            >
              <Languages className="w-3.5 h-3.5 text-sentinel-primary" />
              <span>{lang === "ar" ? "English" : "العربية"}</span>
            </button>

            <button
              type="button"
              onClick={toggleTheme}
              className="h-9 px-3 rounded-md border border-border-subtle bg-elevated text-xs text-ink-primary flex items-center gap-1.5"
            >
              {theme === "dark" ? (
                <>
                  <Sun className="w-3.5 h-3.5 text-sentinel-warning" />
                  <span>{t("common.lightTheme")}</span>
                </>
              ) : (
                <>
                  <Moon className="w-3.5 h-3.5 text-sentinel-primary" />
                  <span>{t("common.darkTheme")}</span>
                </>
              )}
            </button>
          </div>
        </div>
      )}
    </header>
  );
}
