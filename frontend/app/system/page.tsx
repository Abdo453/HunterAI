"use client";

import React, { useCallback, useEffect, useState } from "react";
import {
  Cpu,
  HeartPulse,
  PackageCheck,
  KeyRound,
  Save,
  RefreshCw,
  Loader2,
  ChevronDown,
  ChevronRight,
  AlertTriangle,
} from "lucide-react";
import HardwareTelemetryCard from "@/components/HardwareTelemetryCard";
import TokenCostPanel from "@/components/TokenCostPanel";
import { usePlatform } from "@/lib/platform-context";
import { useI18n } from "@/lib/i18n";
import { useUnsavedChangesGuard } from "@/hooks/use-unsaved-changes-guard";
import { sanitizePlainTerminalText } from "@/lib/terminal-sanitizer";

interface DiagnosticCheck {
  component: string;
  status: string;
  message: string;
}

interface DiagnosticsReport {
  health_score?: number;
  score_label?: string;
  timestamp?: string;
  checks?: DiagnosticCheck[];
}

interface ModelRow {
  name: string;
  provider: string;
  status: string;
  is_local?: boolean;
}

interface ControlSettingsData {
  upstream_proxy?: string;
  burp_agent_port?: number;
  max_concurrent_agents?: number;
  rate_limit_rps?: number;
  llm_policy?: string;
  default_model?: string;
  has_gemini_key?: boolean;
  has_deepseek_key?: boolean;
  has_nvidia_key?: boolean;
  has_anthropic_key?: boolean;
  has_openai_key?: boolean;
  has_openrouter_key?: boolean;
}

interface EnvSettingsData {
  providers?: string[];
  default_provider?: string;
  default_model?: string;
  ollama_host?: string;
  keys?: Record<string, { configured?: boolean; key_masked?: string | null }>;
}

const POLICIES = ["balanced", "cloud_first", "local_first", "local_only", "cloud_only"] as const;

function isModelHealthy(status: string): boolean {
  const upper = status.toUpperCase();
  return upper === "READY" || upper === "RUNNING" || upper.startsWith("CONFIGURED") || upper === "ONLINE";
}

export default function SystemPage() {
  const { apiJson } = usePlatform();
  const { t } = useI18n();

  const [models, setModels] = useState<ModelRow[]>([]);
  const [catalogChoices, setCatalogChoices] = useState<Array<{ id: string; label: string }>>([]);

  // Settings
  const [proxyUrl, setProxyUrl] = useState<string>("http://127.0.0.1:8080");
  const [burpPort, setBurpPort] = useState<number>(8085);
  const [maxAgents, setMaxAgents] = useState<number>(5);
  const [rateRps, setRateRps] = useState<number>(2.0);
  const [llmPolicy, setLlmPolicy] = useState<string>("balanced");
  const [defaultModel, setDefaultModel] = useState<string>("auto");
  const [settingsDirty, setSettingsDirty] = useState<boolean>(false);
  const [ctrlSettings, setCtrlSettings] = useState<ControlSettingsData | null>(null);
  const [envSettings, setEnvSettings] = useState<EnvSettingsData | null>(null);
  const [settingsMsg, setSettingsMsg] = useState<string>("");

  // Provider defaults & write-only API key updater (separate so saving a key NEVER clobbers HUNTER_DEFAULT_PROVIDER)
  const [defaultProviderInput, setDefaultProviderInput] = useState<string>("");
  const [ollamaHostInput, setOllamaHostInput] = useState<string>("");
  const [providerMsg, setProviderMsg] = useState<string>("");
  const [keyProvider, setKeyProvider] = useState<string>("nvidia");
  const [keyValue, setKeyValue] = useState<string>("");
  const [keyMsg, setKeyMsg] = useState<string>("");

  // Diagnostics & Install Plan
  const [diagReport, setDiagReport] = useState<DiagnosticsReport | null>(null);
  const [readinessJson, setReadinessJson] = useState<Record<string, unknown> | null>(null);
  const [installPlan, setInstallPlan] = useState<Record<string, unknown> | null>(null);
  const [showRawReadiness, setShowRawReadiness] = useState<boolean>(false);
  const [showRawPlan, setShowRawPlan] = useState<boolean>(false);
  const [runningDiag, setRunningDiag] = useState<boolean>(false);

  useUnsavedChangesGuard({
    isDirty: settingsDirty,
    message: t("settings.unsavedWarning"),
  });

  const loadSystemData = useCallback(async () => {
    const [modR, catR, cSetR, eSetR, planR] = await Promise.all([
      apiJson<{ models?: ModelRow[] }>("/api/control/models"),
      apiJson<{ choices?: Array<{ id?: string; label?: string }> }>("/api/models/catalog"),
      apiJson<{ settings?: ControlSettingsData }>("/api/control/settings"),
      apiJson<EnvSettingsData>("/api/settings"),
      apiJson<Record<string, unknown>>("/api/diagnostics/install-plan"),
    ]);

    if (modR.ok && Array.isArray(modR.data?.models)) setModels(modR.data.models);
    if (catR.ok && Array.isArray(catR.data?.choices)) {
      setCatalogChoices(
        catR.data.choices
          .filter((c): c is { id: string; label?: string } => Boolean(c?.id))
          .map((c) => ({ id: c.id, label: c.label || c.id }))
      );
    }
    if (cSetR.ok && cSetR.data?.settings) {
      const s = cSetR.data.settings;
      setCtrlSettings(s);
      if (s.upstream_proxy) setProxyUrl(s.upstream_proxy);
      if (typeof s.burp_agent_port === "number") setBurpPort(s.burp_agent_port);
      if (typeof s.max_concurrent_agents === "number") setMaxAgents(s.max_concurrent_agents);
      if (typeof s.rate_limit_rps === "number") setRateRps(s.rate_limit_rps);
      if (s.llm_policy) setLlmPolicy(s.llm_policy);
      if (s.default_model) setDefaultModel(s.default_model);
      setSettingsDirty(false);
    }
    if (eSetR.ok && eSetR.data) {
      setEnvSettings(eSetR.data);
      if (eSetR.data.default_provider) setDefaultProviderInput(eSetR.data.default_provider);
      if (eSetR.data.ollama_host) setOllamaHostInput(eSetR.data.ollama_host);
    }
    if (planR.ok && planR.data) setInstallPlan(planR.data);
  }, [apiJson]);

  useEffect(() => {
    void loadSystemData();
  }, [loadSystemData]);

  const saveControlSettings = async (e: React.FormEvent) => {
    e.preventDefault();
    setSettingsMsg("");
    const res = await apiJson<{ updated?: string[] }>("/api/control/settings", {
      method: "POST",
      body: {
        upstream_proxy: proxyUrl.trim(),
        burp_agent_port: burpPort,
        max_concurrent_agents: maxAgents,
        rate_limit_rps: rateRps,
        llm_policy: llmPolicy,
        default_model: defaultModel,
      },
    });
    if (res.ok) {
      setSettingsDirty(false);
      setSettingsMsg(`${t("common.save")} (${(res.data?.updated || []).join(", ")})`);
    } else {
      setSettingsMsg(res.error || t("common.error"));
    }
  };

  // Send {[keyProvider]: keyValue} WITHOUT `provider` field so HUNTER_DEFAULT_PROVIDER is NEVER clobbered!
  const saveApiKey = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!keyValue.trim()) return;
    setKeyMsg("");
    const res = await apiJson<{ note?: string; error?: string }>("/api/settings/save", {
      method: "POST",
      body: { [keyProvider]: keyValue.trim() },
    });
    setKeyValue("");
    setKeyMsg(res.ok ? res.data?.note || t("settings.keySavedOk") : res.error || res.data?.error || t("common.error"));
    await loadSystemData();
  };

  const saveProviderDefaults = async (e: React.FormEvent) => {
    e.preventDefault();
    setProviderMsg("");
    const payload: Record<string, string> = {};
    if (defaultProviderInput.trim()) payload.default_provider = defaultProviderInput.trim();
    if (ollamaHostInput.trim()) payload.ollama_host = ollamaHostInput.trim();
    if (Object.keys(payload).length === 0) return;

    const res = await apiJson<{ note?: string; error?: string }>("/api/settings/save", {
      method: "POST",
      body: payload,
    });
    setProviderMsg(res.ok ? res.data?.note || t("common.save") : res.error || res.data?.error || t("common.error"));
    await loadSystemData();
  };

  const runDiagnostics = async () => {
    setRunningDiag(true);
    const [dR, rR] = await Promise.all([
      apiJson<DiagnosticsReport>("/api/control/diagnostics/run"),
      apiJson<Record<string, unknown>>("/api/diagnostics/readiness"),
    ]);
    setRunningDiag(false);
    if (dR.ok && dR.data) setDiagReport(dR.data);
    if (rR.ok && rR.data) setReadinessJson(rR.data);
  };

  const maskedEntries = Object.entries(envSettings?.keys || {});

  // Parse structured install plan rows if available
  const installSteps = Array.isArray(installPlan?.missing_tools)
    ? (installPlan.missing_tools as Array<Record<string, unknown> | string>)
    : Array.isArray(installPlan?.steps)
      ? (installPlan.steps as Array<Record<string, unknown> | string>)
      : [];

  return (
    <div className="space-y-5">
      {/* Live Hardware Telemetry + Persisted Token Cost Breakdown */}
      <div className="grid grid-cols-1 xl:grid-cols-12 gap-5">
        <div className="xl:col-span-6">
          <HardwareTelemetryCard />
        </div>
        <div className="xl:col-span-6">
          <TokenCostPanel />
        </div>
      </div>

      {/* AI Models + Routing Policy */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-5">
        <section className="lg:col-span-7 sentinel-surface p-4 space-y-3">
          <div className="flex items-center justify-between pb-2 border-b border-border-subtle">
            <div className="flex items-center gap-2">
              <Cpu className="w-4 h-4 text-sentinel-ai" />
              <h1 className="text-sm font-semibold text-ink-primary">{t("models.title")}</h1>
            </div>
            <button
              type="button"
              onClick={() => void loadSystemData()}
              className="h-8 px-2.5 rounded border border-border-subtle bg-elevated text-xs flex items-center gap-1"
            >
              <RefreshCw className="w-3.5 h-3.5" />
              <span>{t("models.scanModels")}</span>
            </button>
          </div>

          <div className="overflow-x-auto border border-border-subtle rounded bg-inset max-h-60 overflow-y-auto">
            <table className="w-full text-xs border-collapse">
              <thead className="bg-elevated border-b border-border-subtle text-ink-muted sticky top-0">
                <tr>
                  <th className="py-2 px-3 text-start">{t("models.colModel")}</th>
                  <th className="py-2 px-3 text-start">{t("models.colProvider")}</th>
                  <th className="py-2 px-3 text-start">{t("models.colStatus")}</th>
                  <th className="py-2 px-3 text-start">{t("models.colType")}</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border-subtle font-mono">
                {models.map((m, idx) => (
                  <tr key={`${m.name}-${idx}`}>
                    <td className="py-1.5 px-3 text-ink-primary ltr-isolate">{m.name}</td>
                    <td className="py-1.5 px-3 text-ink-secondary">{m.provider}</td>
                    <td className="py-1.5 px-3">
                      <span
                        className={
                          isModelHealthy(m.status || "")
                            ? "text-sentinel-success"
                            : "text-sentinel-warning"
                        }
                      >
                        {m.status}
                      </span>
                    </td>
                    <td className="py-1.5 px-3 text-ink-muted">
                      {m.is_local ? t("models.localPrivateBadge") : t("models.cloudFallbackBadge")}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>

        <section className="lg:col-span-5 sentinel-surface p-4 space-y-3">
          <div className="flex items-center justify-between gap-2 pb-2 border-b border-border-subtle">
            <div className="flex items-center gap-2">
              <Save className="w-4 h-4 text-sentinel-primary" />
              <h2 className="text-sm font-semibold text-ink-primary">{t("models.defaultSettingsTitle")}</h2>
            </div>
            {settingsDirty && (
              <span className="inline-flex items-center gap-1 text-[11px] font-mono px-2 py-0.5 rounded bg-sentinel-warning/15 text-sentinel-warning border border-sentinel-warning/35">
                <AlertTriangle className="w-3 h-3" />
                <span>{t("editor.modifiedBadge")}</span>
              </span>
            )}
          </div>

          <form onSubmit={saveControlSettings} className="space-y-2.5 text-xs">
            <div className="space-y-1">
              <label htmlFor="sys-policy" className="text-ink-muted">{t("settings.routingPolicyLabel")}</label>
              <select
                id="sys-policy"
                value={llmPolicy}
                onChange={(e) => {
                  setLlmPolicy(e.target.value);
                  setSettingsDirty(true);
                }}
                className="w-full h-9 px-2.5 rounded bg-inset border border-border-subtle font-mono"
              >
                {POLICIES.map((p) => (
                  <option key={p} value={p}>{p}</option>
                ))}
              </select>
            </div>

            <div className="space-y-1">
              <label htmlFor="sys-model" className="text-ink-muted">{t("models.activeModelLabel")}</label>
              <select
                id="sys-model"
                value={defaultModel}
                onChange={(e) => {
                  setDefaultModel(e.target.value);
                  setSettingsDirty(true);
                }}
                className="w-full h-9 px-2.5 rounded bg-inset border border-border-subtle font-mono"
              >
                <option value="auto">auto</option>
                {catalogChoices.map((ch, idx) => (
                  <option key={`${ch.id}-${idx}`} value={ch.id}>{ch.label}</option>
                ))}
              </select>
            </div>

            <div className="grid grid-cols-2 gap-2">
              <div className="space-y-1">
                <label htmlFor="sys-proxy" className="text-ink-muted">{t("settings.upstreamProxy")}</label>
                <input
                  id="sys-proxy"
                  type="text"
                  dir="ltr"
                  value={proxyUrl}
                  onChange={(e) => {
                    setProxyUrl(e.target.value);
                    setSettingsDirty(true);
                  }}
                  className="ltr-isolate w-full h-8 px-2.5 rounded bg-inset border border-border-subtle font-mono"
                />
              </div>
              <div className="space-y-1">
                <label htmlFor="sys-burp-port" className="text-ink-muted">{t("settings.burpAgentPort")}</label>
                <input
                  id="sys-burp-port"
                  type="number"
                  value={burpPort}
                  onChange={(e) => {
                    setBurpPort(Number(e.target.value) || 8085);
                    setSettingsDirty(true);
                  }}
                  className="w-full h-8 px-2.5 rounded bg-inset border border-border-subtle font-mono ltr-isolate"
                />
              </div>
              <div className="space-y-1">
                <label htmlFor="sys-agents" className="text-ink-muted">{t("settings.maxConcurrentAgents")}</label>
                <input
                  id="sys-agents"
                  type="number"
                  value={maxAgents}
                  onChange={(e) => {
                    setMaxAgents(Number(e.target.value) || 5);
                    setSettingsDirty(true);
                  }}
                  className="w-full h-8 px-2.5 rounded bg-inset border border-border-subtle font-mono ltr-isolate"
                />
              </div>
              <div className="space-y-1">
                <label htmlFor="sys-rps" className="text-ink-muted">{t("settings.rateLimitRps")}</label>
                <input
                  id="sys-rps"
                  type="number"
                  step="0.5"
                  value={rateRps}
                  onChange={(e) => {
                    setRateRps(Number(e.target.value) || 2);
                    setSettingsDirty(true);
                  }}
                  className="w-full h-8 px-2.5 rounded bg-inset border border-border-subtle font-mono ltr-isolate"
                />
              </div>
            </div>

            <div className="flex items-center justify-between pt-1">
              <button
                type="submit"
                className="min-h-[44px] sm:min-h-[36px] px-4 rounded bg-sentinel-primary text-sentinel-onAccent font-semibold"
              >
                {t("settings.saveSettings")}
              </button>
              {settingsMsg && <span className="font-mono text-sentinel-success">{settingsMsg}</span>}
            </div>
          </form>
        </section>
      </div>

      {/* Masked API Keys + Diagnostics & Readiness */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-5">
        <section className="lg:col-span-5 sentinel-surface p-4 space-y-3">
          <div className="flex items-center gap-2 pb-2 border-b border-border-subtle">
            <KeyRound className="w-4 h-4 text-sentinel-warning" />
            <h2 className="text-sm font-semibold text-ink-primary">{t("settings.apiKeysTitle")}</h2>
          </div>

          <p className="text-xs text-ink-muted">{t("settings.apiKeysNote")}</p>

          <div className="grid grid-cols-2 gap-2 text-xs font-mono">
            {maskedEntries.length > 0 ? (
              maskedEntries.map(([prov, info]) => (
                <div key={prov} className="p-2 rounded bg-elevated border border-border-subtle flex items-center justify-between">
                  <span className="text-ink-primary">{prov}</span>
                  <span className={info.configured ? "text-sentinel-success" : "text-ink-muted"}>
                    {info.configured ? info.key_masked || t("states.configured") : t("states.missing")}
                  </span>
                </div>
              ))
            ) : (
              <>
                <div className="p-2 rounded bg-elevated border border-border-subtle flex justify-between">
                  <span>gemini</span>
                  <span>{ctrlSettings?.has_gemini_key ? t("states.configured") : t("states.missing")}</span>
                </div>
                <div className="p-2 rounded bg-elevated border border-border-subtle flex justify-between">
                  <span>deepseek</span>
                  <span>{ctrlSettings?.has_deepseek_key ? t("states.configured") : t("states.missing")}</span>
                </div>
                <div className="p-2 rounded bg-elevated border border-border-subtle flex justify-between">
                  <span>nvidia</span>
                  <span>{ctrlSettings?.has_nvidia_key ? t("states.configured") : t("states.missing")}</span>
                </div>
                <div className="p-2 rounded bg-elevated border border-border-subtle flex justify-between">
                  <span>openai</span>
                  <span>{ctrlSettings?.has_openai_key ? t("states.configured") : t("states.missing")}</span>
                </div>
              </>
            )}
          </div>

          <form onSubmit={saveApiKey} className="flex flex-wrap gap-2 pt-2 border-t border-border-subtle text-xs">
            <select
              value={keyProvider}
              onChange={(e) => setKeyProvider(e.target.value)}
              aria-label={t("models.colProvider")}
              className="h-8 px-2 rounded bg-inset border border-border-subtle font-mono"
            >
              {Array.from(
                new Set(envSettings?.providers || ["nvidia", "gemini", "deepseek", "openai", "anthropic", "openrouter"])
              ).map((p, idx) => (
                <option key={`${p}-${idx}`} value={p}>{p}</option>
              ))}
            </select>
            <input
              type="password"
              dir="ltr"
              value={keyValue}
              onChange={(e) => setKeyValue(e.target.value)}
              placeholder={t("settings.writeOnlyKeyPlaceholder")}
              aria-label={t("settings.writeOnlyKeyPlaceholder")}
              className="ltr-isolate flex-1 min-w-[140px] h-8 px-2.5 rounded bg-inset border border-border-subtle font-mono"
            />
            <button type="submit" className="h-8 px-3 rounded bg-elevated border border-border-strong font-semibold">
              {t("common.save")}
            </button>
          </form>
          {keyMsg && <div className="text-xs font-mono text-sentinel-success">{keyMsg}</div>}

          {/* Explicit Default Provider & Ollama Host (never silently modified by API key updates) */}
          <form onSubmit={saveProviderDefaults} className="space-y-2 pt-2 border-t border-border-subtle text-xs">
            <div className="font-semibold text-ink-secondary">{t("settings.providerDefaultsTitle")}</div>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
              <input
                type="text"
                dir="ltr"
                value={defaultProviderInput}
                onChange={(e) => setDefaultProviderInput(e.target.value)}
                placeholder={t("settings.defaultProviderPlaceholder")}
                aria-label={t("settings.defaultProviderPlaceholder")}
                className="ltr-isolate h-8 px-2.5 rounded bg-inset border border-border-subtle font-mono"
              />
              <input
                type="text"
                dir="ltr"
                value={ollamaHostInput}
                onChange={(e) => setOllamaHostInput(e.target.value)}
                placeholder="http://127.0.0.1:11434"
                aria-label={t("settings.ollamaHostLabel")}
                className="ltr-isolate h-8 px-2.5 rounded bg-inset border border-border-subtle font-mono"
              />
            </div>
            <div className="flex items-center gap-2">
              <button type="submit" className="h-8 px-3 rounded bg-elevated border border-border-strong font-semibold">
                {t("settings.applyProviderDefaults")}
              </button>
              {providerMsg && <span className="font-mono text-sentinel-success">{providerMsg}</span>}
            </div>
          </form>
        </section>

        <section className="lg:col-span-7 sentinel-surface p-4 space-y-3">
          <div className="flex flex-wrap items-center justify-between gap-2 pb-2 border-b border-border-subtle">
            <div className="flex items-center gap-2">
              <HeartPulse className="w-4 h-4 text-sentinel-success" />
              <h2 className="text-sm font-semibold text-ink-primary">{t("diagnostics.title")}</h2>
            </div>
            <div className="flex items-center gap-2">
              {diagReport?.health_score !== undefined && (
                <span className="font-mono text-xs px-2 py-0.5 rounded bg-sentinel-success/15 text-sentinel-success border border-sentinel-success/35">
                  {diagReport.health_score}% ({diagReport.score_label})
                </span>
              )}
              <button
                type="button"
                disabled={runningDiag}
                onClick={() => void runDiagnostics()}
                className="min-h-[44px] sm:min-h-[32px] px-3 rounded bg-sentinel-primary text-sentinel-onAccent text-xs font-semibold flex items-center gap-1.5"
              >
                {runningDiag && <Loader2 className="w-3.5 h-3.5 animate-spin" />}
                <span>{t("diagnostics.runFullCheck")}</span>
              </button>
            </div>
          </div>

          {diagReport?.checks ? (
            <div className="overflow-x-auto border border-border-subtle rounded bg-inset max-h-56 overflow-y-auto">
              <table className="w-full text-xs border-collapse">
                <thead className="bg-elevated border-b border-border-subtle text-ink-muted sticky top-0">
                  <tr>
                    <th className="py-2 px-3 text-start">{t("diagnostics.colComponent")}</th>
                    <th className="py-2 px-3 text-start">{t("diagnostics.colStatus")}</th>
                    <th className="py-2 px-3 text-start">{t("diagnostics.colMessage")}</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-border-subtle">
                  {diagReport.checks.map((c, idx) => (
                    <tr key={`${c.component || "check"}-${idx}`}>
                      <td className="py-1.5 px-3 font-medium text-ink-primary">{c.component}</td>
                      <td className="py-1.5 px-3 font-mono">
                        <span
                          className={
                            c.status === "PASS"
                              ? "text-sentinel-success"
                              : c.status === "WARN"
                                ? "text-sentinel-warning"
                                : "text-sentinel-danger"
                          }
                        >
                          {c.status}
                        </span>
                      </td>
                      <td className="py-1.5 px-3 text-ink-secondary">{c.message}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <div className="py-8 text-center text-xs text-ink-muted">{t("diagnostics.emptyDiagnostics")}</div>
          )}

          {/* Structured Readiness Summary + Collapsible Raw JSON */}
          {readinessJson && (
            <div className="space-y-2 pt-2 border-t border-border-subtle">
              <div className="grid grid-cols-2 sm:grid-cols-3 gap-2 text-xs">
                {Object.entries(readinessJson)
                  .filter(([, v]) => typeof v !== "object" || v === null)
                  .slice(0, 6)
                  .map(([k, v]) => (
                    <div key={k} className="p-2 rounded bg-elevated border border-border-subtle">
                      <div className="text-[10px] font-mono text-ink-muted truncate">{k}</div>
                      <div className="font-mono text-ink-primary ltr-isolate truncate">{String(v)}</div>
                    </div>
                  ))}
              </div>
              <button
                type="button"
                aria-expanded={showRawReadiness}
                onClick={() => setShowRawReadiness((p) => !p)}
                className="text-[11px] font-mono text-ink-muted hover:text-ink-primary flex items-center gap-1"
              >
                {showRawReadiness ? (
                  <ChevronDown className="w-3.5 h-3.5" />
                ) : (
                  <ChevronRight className="w-3.5 h-3.5 rtl:rotate-180" />
                )}
                <span>{t("diagnostics.toggleRawJson")}</span>
              </button>
              {showRawReadiness && (
                <pre dir="ltr" className="ltr-isolate p-2.5 rounded bg-inset border border-border-subtle font-mono text-[11px] max-h-40 overflow-auto">
                  {sanitizePlainTerminalText(JSON.stringify(readinessJson, null, 2))}
                </pre>
              )}
            </div>
          )}
        </section>
      </div>

      {/* Structured Tool Installation Plan */}
      <section className="sentinel-surface p-4 space-y-3">
        <div className="flex items-center justify-between gap-2 pb-2 border-b border-border-subtle">
          <div className="flex items-center gap-2">
            <PackageCheck className="w-4 h-4 text-sentinel-primary" />
            <h2 className="text-sm font-semibold text-ink-primary">{t("diagnostics.installPlanTitle")}</h2>
          </div>
          <button
            type="button"
            aria-expanded={showRawPlan}
            onClick={() => setShowRawPlan((p) => !p)}
            className="text-xs font-mono text-ink-muted hover:text-ink-primary flex items-center gap-1"
          >
            {showRawPlan ? (
              <ChevronDown className="w-3.5 h-3.5" />
            ) : (
              <ChevronRight className="w-3.5 h-3.5 rtl:rotate-180" />
            )}
            <span>{t("diagnostics.toggleRawJson")}</span>
          </button>
        </div>

        {installSteps.length > 0 ? (
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-2 text-xs">
            {installSteps.slice(0, 12).map((step, idx) => {
              const label =
                typeof step === "string"
                  ? step
                  : String(step.tool || step.name || step.command || `Step ${idx + 1}`);
              const cmd = typeof step === "object" && step ? String(step.command || step.install_cmd || "") : "";
              return (
                <div key={`${label}-${idx}`} className="p-2.5 rounded bg-inset border border-border-subtle space-y-1">
                  <div className="font-mono font-semibold text-ink-primary ltr-isolate">{label}</div>
                  {cmd && <div className="font-mono text-[11px] text-ink-muted ltr-isolate truncate">{cmd}</div>}
                </div>
              );
            })}
          </div>
        ) : (
          <div className="text-xs text-ink-secondary">
            {installPlan ? t("diagnostics.installPlanReady") : t("common.noData")}
          </div>
        )}

        {showRawPlan && (
          <pre dir="ltr" className="ltr-isolate p-3 rounded bg-inset border border-border-subtle font-mono text-[11px] text-ink-secondary max-h-52 overflow-auto">
            {sanitizePlainTerminalText(JSON.stringify(installPlan || { plan: null }, null, 2))}
          </pre>
        )}
      </section>
    </div>
  );
}
