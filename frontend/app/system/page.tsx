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
} from "lucide-react";
import { usePlatform } from "@/lib/platform-context";
import { useI18n } from "@/lib/i18n";

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
  keys?: Record<string, { configured?: boolean; key_masked?: string | null }>;
}

const POLICIES = ["cloud_first", "local_first", "local_only", "cloud_only"] as const;

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
  const [llmPolicy, setLlmPolicy] = useState<string>("cloud_first");
  const [defaultModel, setDefaultModel] = useState<string>("auto");
  const [ctrlSettings, setCtrlSettings] = useState<ControlSettingsData | null>(null);
  const [envSettings, setEnvSettings] = useState<EnvSettingsData | null>(null);
  const [settingsMsg, setSettingsMsg] = useState<string>("");

  // Key Updater (write-only)
  const [keyProvider, setKeyProvider] = useState<string>("nvidia");
  const [keyValue, setKeyValue] = useState<string>("");
  const [keyMsg, setKeyMsg] = useState<string>("");

  // Diagnostics & Install Plan
  const [diagReport, setDiagReport] = useState<DiagnosticsReport | null>(null);
  const [readinessJson, setReadinessJson] = useState<Record<string, unknown> | null>(null);
  const [installPlan, setInstallPlan] = useState<Record<string, unknown> | null>(null);
  const [runningDiag, setRunningDiag] = useState<boolean>(false);

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
    }
    if (eSetR.ok && eSetR.data) setEnvSettings(eSetR.data);
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
    setSettingsMsg(res.ok ? `${t("common.save")} (${(res.data?.updated || []).join(", ")})` : res.error || "Save failed");
  };

  const saveApiKey = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!keyValue.trim()) return;
    setKeyMsg("");
    const res = await apiJson<{ note?: string; error?: string }>("/api/settings/save", {
      method: "POST",
      body: { provider: keyProvider, api_key: keyValue.trim() },
    });
    setKeyValue("");
    setKeyMsg(res.ok ? res.data?.note || "Saved" : res.error || res.data?.error || "Failed");
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

  return (
    <div className="space-y-5">
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
                          m.status === "RUNNING" || m.status.startsWith("CONFIGURED")
                            ? "text-sentinel-success"
                            : "text-sentinel-warning"
                        }
                      >
                        {m.status}
                      </span>
                    </td>
                    <td className="py-1.5 px-3 text-ink-muted">{m.is_local ? "Local" : "Cloud"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>

        <section className="lg:col-span-5 sentinel-surface p-4 space-y-3">
          <div className="flex items-center gap-2 pb-2 border-b border-border-subtle">
            <Save className="w-4 h-4 text-sentinel-primary" />
            <h2 className="text-sm font-semibold text-ink-primary">{t("models.defaultSettingsTitle")}</h2>
          </div>

          <form onSubmit={saveControlSettings} className="space-y-2.5 text-xs">
            <div className="space-y-1">
              <label htmlFor="sys-policy" className="text-ink-muted">Routing Policy</label>
              <select
                id="sys-policy"
                value={llmPolicy}
                onChange={(e) => setLlmPolicy(e.target.value)}
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
                onChange={(e) => setDefaultModel(e.target.value)}
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
                  onChange={(e) => setProxyUrl(e.target.value)}
                  className="ltr-isolate w-full h-8 px-2.5 rounded bg-inset border border-border-subtle font-mono"
                />
              </div>
              <div className="space-y-1">
                <label htmlFor="sys-burp-port" className="text-ink-muted">{t("settings.burpAgentPort")}</label>
                <input
                  id="sys-burp-port"
                  type="number"
                  value={burpPort}
                  onChange={(e) => setBurpPort(Number(e.target.value) || 8085)}
                  className="w-full h-8 px-2.5 rounded bg-inset border border-border-subtle font-mono ltr-isolate"
                />
              </div>
              <div className="space-y-1">
                <label htmlFor="sys-agents" className="text-ink-muted">{t("settings.maxConcurrentAgents")}</label>
                <input
                  id="sys-agents"
                  type="number"
                  value={maxAgents}
                  onChange={(e) => setMaxAgents(Number(e.target.value) || 5)}
                  className="w-full h-8 px-2.5 rounded bg-inset border border-border-subtle font-mono ltr-isolate"
                />
              </div>
              <div className="space-y-1">
                <label htmlFor="sys-rps" className="text-ink-muted">Rate Limit (RPS)</label>
                <input
                  id="sys-rps"
                  type="number"
                  step="0.5"
                  value={rateRps}
                  onChange={(e) => setRateRps(Number(e.target.value) || 2)}
                  className="w-full h-8 px-2.5 rounded bg-inset border border-border-subtle font-mono ltr-isolate"
                />
              </div>
            </div>

            <div className="flex items-center justify-between pt-1">
              <button
                type="submit"
                className="h-9 px-4 rounded bg-sentinel-primary text-sentinel-onAccent font-semibold"
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
                    {info.configured ? info.key_masked || "SET" : "MISSING"}
                  </span>
                </div>
              ))
            ) : (
              <>
                <div className="p-2 rounded bg-elevated border border-border-subtle flex justify-between">
                  <span>gemini</span>
                  <span>{ctrlSettings?.has_gemini_key ? "SET" : "MISSING"}</span>
                </div>
                <div className="p-2 rounded bg-elevated border border-border-subtle flex justify-between">
                  <span>deepseek</span>
                  <span>{ctrlSettings?.has_deepseek_key ? "SET" : "MISSING"}</span>
                </div>
                <div className="p-2 rounded bg-elevated border border-border-subtle flex justify-between">
                  <span>nvidia</span>
                  <span>{ctrlSettings?.has_nvidia_key ? "SET" : "MISSING"}</span>
                </div>
                <div className="p-2 rounded bg-elevated border border-border-subtle flex justify-between">
                  <span>openai</span>
                  <span>{ctrlSettings?.has_openai_key ? "SET" : "MISSING"}</span>
                </div>
              </>
            )}
          </div>

          <form onSubmit={saveApiKey} className="flex flex-wrap gap-2 pt-2 border-t border-border-subtle text-xs">
            <select
              value={keyProvider}
              onChange={(e) => setKeyProvider(e.target.value)}
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
              placeholder="Write-only API key..."
              className="ltr-isolate flex-1 min-w-[140px] h-8 px-2.5 rounded bg-inset border border-border-subtle font-mono"
            />
            <button type="submit" className="h-8 px-3 rounded bg-elevated border border-border-strong font-semibold">
              {t("common.save")}
            </button>
          </form>
          {keyMsg && <div className="text-xs font-mono text-sentinel-success">{keyMsg}</div>}
        </section>

        <section className="lg:col-span-7 sentinel-surface p-4 space-y-3">
          <div className="flex flex-wrap items-center justify-between gap-2 pb-2 border-b border-border-subtle">
            <div className="flex items-center gap-2">
              <HeartPulse className="w-4 h-4 text-sentinel-success" />
              <h2 className="text-sm font-semibold text-ink-primary">{t("diagnostics.title")}</h2>
            </div>
            <div className="flex items-center gap-2">
              {diagReport?.health_score !== undefined && (
                <span className="font-mono text-xs px-2 py-0.5 rounded bg-[var(--accent-success-bg)] text-sentinel-success">
                  {diagReport.health_score}% ({diagReport.score_label})
                </span>
              )}
              <button
                type="button"
                disabled={runningDiag}
                onClick={() => void runDiagnostics()}
                className="h-8 px-3 rounded bg-sentinel-primary text-sentinel-onAccent text-xs font-semibold flex items-center gap-1.5"
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

          {readinessJson && (
            <pre dir="ltr" className="ltr-isolate p-2.5 rounded bg-inset border border-border-subtle font-mono text-[11px] max-h-36 overflow-auto">
              {JSON.stringify(readinessJson, null, 2)}
            </pre>
          )}
        </section>
      </div>

      {/* Install Plan */}
      <section className="sentinel-surface p-4 space-y-2">
        <div className="flex items-center gap-2 pb-2 border-b border-border-subtle">
          <PackageCheck className="w-4 h-4 text-sentinel-primary" />
          <h2 className="text-sm font-semibold text-ink-primary">Tool Installation Plan</h2>
        </div>
        <pre dir="ltr" className="ltr-isolate p-3 rounded bg-inset border border-border-subtle font-mono text-[11px] text-ink-secondary max-h-52 overflow-auto">
          {JSON.stringify(installPlan || { plan: null }, null, 2)}
        </pre>
      </section>
    </div>
  );
}
