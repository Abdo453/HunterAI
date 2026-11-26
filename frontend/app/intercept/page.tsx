"use client";

import React, { useCallback, useEffect, useState } from "react";
import {
  Radar,
  Globe,
  FileSearch,
  KeyRound,
  Unlock,
  Send,
  RefreshCw,
  Loader2,
} from "lucide-react";
import { usePlatform } from "@/lib/platform-context";
import { useI18n } from "@/lib/i18n";

interface BurpStatusPayload {
  proxy?: { host?: string; port?: number; online?: boolean; label?: string };
  agent?: { host?: string; port?: number; online?: boolean; label?: string };
}

interface TrafficItem {
  id: string;
  time: string;
  method: string;
  host: string;
  path: string;
  status: number;
  length: number;
}

export default function InterceptPage() {
  const { selectedEngagement, targetDomain, sendToRepeater, apiJson } = usePlatform();
  const { t } = useI18n();

  const [burpStatus, setBurpStatus] = useState<BurpStatusPayload | null>(null);
  const [traffic, setTraffic] = useState<TrafficItem[]>([]);
  const [browserState, setBrowserState] = useState<Record<string, unknown> | null>(null);

  // Log Inspector
  const [logText, setLogText] = useState<string>("");
  const [minRisk, setMinRisk] = useState<number>(6);
  const [inspectRes, setInspectRes] = useState<Record<string, unknown> | null>(null);
  const [inspecting, setInspecting] = useState<boolean>(false);

  // Browser Studio
  const [browseUrl, setBrowseUrl] = useState<string>("");
  const [browseRes, setBrowseRes] = useState<Record<string, unknown> | null>(null);
  const [browsing, setBrowsing] = useState<boolean>(false);

  // Recon Trio
  const [dorkDomain, setDorkDomain] = useState<string>(targetDomain || "");
  const [dorksOut, setDorksOut] = useState<{ google_dorks?: string[]; github_dorks?: string[] } | null>(null);
  const [jsContent, setJsContent] = useState<string>("");
  const [jsOut, setJsOut] = useState<Record<string, unknown> | null>(null);
  const [bypassUrl, setBypassUrl] = useState<string>("");
  const [bypassOut, setBypassOut] = useState<{ variations?: unknown[] } | null>(null);

  useEffect(() => {
    if (selectedEngagement?.target) {
      setDorkDomain(selectedEngagement.target);
    }
  }, [selectedEngagement]);

  const loadFeed = useCallback(async () => {
    const [stR, trR, brR] = await Promise.all([
      apiJson<BurpStatusPayload>("/api/burp/status"),
      apiJson<{ items?: TrafficItem[] }>("/api/burp/traffic?limit=50"),
      apiJson<Record<string, unknown>>("/api/control/browser"),
    ]);
    if (stR.ok && stR.data) setBurpStatus(stR.data);
    if (trR.ok && Array.isArray(trR.data?.items)) setTraffic(trR.data.items);
    if (brR.ok && brR.data) setBrowserState(brR.data);
  }, [apiJson]);

  useEffect(() => {
    void loadFeed();
  }, [loadFeed]);

  const inspectBurpLogs = async (e: React.FormEvent) => {
    e.preventDefault();
    setInspecting(true);
    const res = await apiJson<Record<string, unknown>>("/api/enhanced/burp/inspect", {
      method: "POST",
      body: {
        source: logText.trim() ? "pasted" : "live",
        content_text: logText.trim() || null,
        target: selectedEngagement?.target || dorkDomain || undefined,
        min_risk: minRisk,
      },
    });
    setInspecting(false);
    setInspectRes(res.data || { error: res.error });
  };

  const launchBrowserExplore = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!browseUrl.trim()) return;
    setBrowsing(true);
    const res = await apiJson<Record<string, unknown>>("/api/enhanced/browser/explore", {
      method: "POST",
      body: { target_url: browseUrl.trim(), headless: true, max_pages: 5 },
    });
    setBrowsing(false);
    setBrowseRes(res.data || { error: res.error });
  };

  const fetchDorks = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!dorkDomain.trim()) return;
    const res = await apiJson<{ google_dorks?: string[]; github_dorks?: string[] }>(
      `/api/recon/dorks?domain=${encodeURIComponent(dorkDomain.trim())}`
    );
    if (res.ok && res.data) setDorksOut(res.data);
  };

  const mineJs = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!jsContent.trim()) return;
    const res = await apiJson<Record<string, unknown>>("/api/recon/mine-js", {
      method: "POST",
      body: { content: jsContent, source: "intercept_workbench" },
    });
    if (res.ok && res.data) setJsOut(res.data);
  };

  const gen403Bypass = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!bypassUrl.trim()) return;
    const res = await apiJson<{ variations?: unknown[] }>(
      `/api/recon/403-bypasses?url=${encodeURIComponent(bypassUrl.trim())}`
    );
    if (res.ok && res.data) setBypassOut(res.data);
  };

  return (
    <div className="space-y-5">
      {/* Burp 8080/8085 Status & Live Traffic Feed */}
      <section className="sentinel-surface p-4 space-y-3">
        <div className="flex flex-wrap items-center justify-between gap-2 pb-3 border-b border-border-subtle">
          <div className="flex items-center gap-2">
            <Radar className="w-4 h-4 text-sentinel-primary" />
            <h1 className="text-sm font-semibold text-ink-primary">{t("burp.title")}</h1>
          </div>
          <div className="flex flex-wrap items-center gap-2 text-xs font-mono">
            <span
              className={`px-2.5 py-1 rounded-full border ${
                burpStatus?.proxy?.online
                  ? "bg-[var(--accent-success-bg)] text-sentinel-success border-[var(--accent-success)]/35"
                  : "bg-[var(--accent-warning-bg)] text-sentinel-warning border-[var(--accent-warning)]/35"
              }`}
            >
              Proxy 8080: {burpStatus?.proxy?.online ? t("status.connected") : t("status.offline")}
            </span>
            <span
              className={`px-2.5 py-1 rounded-full border ${
                burpStatus?.agent?.online
                  ? "bg-[var(--accent-success-bg)] text-sentinel-success border-[var(--accent-success)]/35"
                  : "bg-elevated text-ink-muted border-border-subtle"
              }`}
            >
              Agent 8085: {burpStatus?.agent?.online ? t("status.connected") : t("status.standby")}
            </span>
            <button
              type="button"
              onClick={() => void loadFeed()}
              className="h-8 px-2.5 rounded border border-border-subtle bg-elevated text-ink-primary flex items-center gap-1"
            >
              <RefreshCw className="w-3.5 h-3.5" />
              <span>{t("common.refresh")}</span>
            </button>
          </div>
        </div>

        {traffic.length === 0 ? (
          <div className="py-6 text-center text-xs text-ink-muted">{t("studio.noTraffic")}</div>
        ) : (
          <div className="overflow-x-auto border border-border-subtle rounded-md bg-inset max-h-72 overflow-y-auto">
            <table className="w-full text-xs border-collapse">
              <thead className="bg-elevated border-b border-border-subtle text-ink-muted sticky top-0">
                <tr>
                  <th className="py-2 px-3 text-start">Time</th>
                  <th className="py-2 px-3 text-start">Method</th>
                  <th className="py-2 px-3 text-start">Host</th>
                  <th className="py-2 px-3 text-start">Path</th>
                  <th className="py-2 px-3 text-start">Status</th>
                  <th className="py-2 px-3 text-start">Repeater</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border-subtle font-mono">
                {traffic.map((tx, idx) => (
                  <tr key={`${tx.id || `${tx.method}-${tx.host}${tx.path}`}-${idx}`} className="hover:bg-elevated/60 ltr-isolate">
                    <td className="py-1.5 px-3 text-ink-muted whitespace-nowrap">{tx.time}</td>
                    <td className="py-1.5 px-3 text-sentinel-primary font-semibold">{tx.method}</td>
                    <td className="py-1.5 px-3 text-ink-primary max-w-[160px] truncate">{tx.host}</td>
                    <td className="py-1.5 px-3 text-ink-secondary max-w-[240px] truncate">{tx.path}</td>
                    <td className="py-1.5 px-3 tabular-nums">{tx.status}</td>
                    <td className="py-1.5 px-3">
                      <button
                        type="button"
                        onClick={() =>
                          sendToRepeater({
                            rawRequest: `${tx.method} ${tx.path} HTTP/1.1\nHost: ${tx.host}\nUser-Agent: HunterAI/2.0\n\n`,
                            targetUrl: `http://${tx.host}${tx.path}`,
                          })
                        }
                        className="px-2 py-0.5 rounded bg-[var(--accent-primary-bg)] border border-[var(--accent-primary)]/40 text-sentinel-primary flex items-center gap-1"
                      >
                        <Send className="w-3 h-3" />
                        <span>Repeater</span>
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>

      {/* Burp XML/JSON/HAR Inspector + Playwright Browser Studio */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-5">
        <section className="lg:col-span-6 sentinel-surface p-4 space-y-3">
          <div className="flex items-center gap-2 pb-2 border-b border-border-subtle">
            <FileSearch className="w-4 h-4 text-sentinel-warning" />
            <h2 className="text-sm font-semibold text-ink-primary">{t("burp.inspectorTitle")}</h2>
          </div>

          <form onSubmit={inspectBurpLogs} className="space-y-2.5 text-xs">
            <textarea
              rows={5}
              dir="ltr"
              value={logText}
              onChange={(e) => setLogText(e.target.value)}
              placeholder={t("burp.pasteTrafficPlaceholder")}
              className="ltr-isolate w-full p-2.5 rounded bg-inset border border-border-subtle font-mono"
            />
            <div className="flex flex-wrap items-center gap-3">
              <label className="flex items-center gap-2 text-ink-muted">
                <span>{t("burp.minRiskLabel")}:</span>
                <input
                  type="number"
                  step="0.5"
                  min={0}
                  max={10}
                  value={minRisk}
                  onChange={(e) => setMinRisk(Number(e.target.value) || 6)}
                  className="w-16 h-8 px-2 rounded bg-inset border border-border-subtle font-mono ltr-isolate"
                />
              </label>
              <button
                type="submit"
                disabled={inspecting}
                className="h-8 px-3 rounded bg-sentinel-primary text-sentinel-onAccent font-semibold flex items-center gap-1.5"
              >
                {inspecting && <Loader2 className="w-3.5 h-3.5 animate-spin" />}
                <span>{t("burp.inspectLogs")}</span>
              </button>
            </div>
          </form>

          {inspectRes && (
            <pre dir="ltr" className="ltr-isolate p-3 rounded bg-inset border border-border-subtle font-mono text-[11px] max-h-48 overflow-auto">
              {JSON.stringify(inspectRes, null, 2)}
            </pre>
          )}
        </section>

        <section className="lg:col-span-6 sentinel-surface p-4 space-y-3">
          <div className="flex items-center justify-between pb-2 border-b border-border-subtle">
            <div className="flex items-center gap-2">
              <Globe className="w-4 h-4 text-sentinel-ai" />
              <h2 className="text-sm font-semibold text-ink-primary">{t("browser.title")}</h2>
            </div>
            <span className="text-xs font-mono px-2 py-0.5 rounded bg-elevated border border-border-subtle text-sentinel-primary">
              {String(browserState?.connection_status || "CHECKING")}
            </span>
          </div>

          <div className="text-xs font-mono text-ink-muted ltr-isolate">
            {String(browserState?.browser_type || "Chromium")} · {String(browserState?.chrome_binary || "")}
          </div>

          <form onSubmit={launchBrowserExplore} className="flex gap-2 text-xs">
            <input
              type="text"
              dir="ltr"
              value={browseUrl}
              onChange={(e) => setBrowseUrl(e.target.value)}
              placeholder={t("browser.exploreUrlPlaceholder")}
              className="ltr-isolate flex-1 h-9 px-3 rounded bg-inset border border-border-subtle font-mono"
            />
            <button
              type="submit"
              disabled={browsing}
              className="h-9 px-3 rounded bg-sentinel-primary text-sentinel-onAccent font-semibold flex items-center gap-1.5"
            >
              {browsing && <Loader2 className="w-3.5 h-3.5 animate-spin" />}
              <span>{t("browser.launchExplore")}</span>
            </button>
          </form>

          {browseRes && (
            <pre dir="ltr" className="ltr-isolate p-3 rounded bg-inset border border-border-subtle font-mono text-[11px] max-h-48 overflow-auto">
              {JSON.stringify(browseRes, null, 2)}
            </pre>
          )}
        </section>
      </div>

      {/* Recon Tools: Dorks, JS Secret Miner, 403 Bypass */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-5">
        <section className="sentinel-surface p-4 space-y-3">
          <div className="flex items-center gap-2 pb-2 border-b border-border-subtle">
            <FileSearch className="w-4 h-4 text-sentinel-primary" />
            <h2 className="text-sm font-semibold text-ink-primary">Google & GitHub Dorks</h2>
          </div>
          <form onSubmit={fetchDorks} className="flex gap-2 text-xs">
            <input
              type="text"
              dir="ltr"
              value={dorkDomain}
              onChange={(e) => setDorkDomain(e.target.value)}
              placeholder="example.com"
              className="ltr-isolate flex-1 h-8 px-2.5 rounded bg-inset border border-border-subtle font-mono"
            />
            <button type="submit" className="h-8 px-3 rounded bg-elevated border border-border-strong font-semibold">
              Generate
            </button>
          </form>
          {dorksOut && (
            <pre dir="ltr" className="ltr-isolate p-2.5 rounded bg-inset border border-border-subtle font-mono text-[11px] max-h-44 overflow-auto">
              {JSON.stringify(dorksOut, null, 2)}
            </pre>
          )}
        </section>

        <section className="sentinel-surface p-4 space-y-3">
          <div className="flex items-center gap-2 pb-2 border-b border-border-subtle">
            <KeyRound className="w-4 h-4 text-sentinel-danger" />
            <h2 className="text-sm font-semibold text-ink-primary">JS Secret & Route Miner</h2>
          </div>
          <form onSubmit={mineJs} className="space-y-2 text-xs">
            <textarea
              rows={3}
              dir="ltr"
              value={jsContent}
              onChange={(e) => setJsContent(e.target.value)}
              placeholder="Paste JavaScript bundle snippet..."
              className="ltr-isolate w-full p-2 rounded bg-inset border border-border-subtle font-mono text-[11px]"
            />
            <button type="submit" className="h-8 px-3 rounded bg-elevated border border-border-strong font-semibold">
              Mine Secrets
            </button>
          </form>
          {jsOut && (
            <pre dir="ltr" className="ltr-isolate p-2.5 rounded bg-inset border border-border-subtle font-mono text-[11px] max-h-36 overflow-auto">
              {JSON.stringify(jsOut, null, 2)}
            </pre>
          )}
        </section>

        <section className="sentinel-surface p-4 space-y-3">
          <div className="flex items-center gap-2 pb-2 border-b border-border-subtle">
            <Unlock className="w-4 h-4 text-sentinel-warning" />
            <h2 className="text-sm font-semibold text-ink-primary">403 Bypass Generator</h2>
          </div>
          <form onSubmit={gen403Bypass} className="flex gap-2 text-xs">
            <input
              type="text"
              dir="ltr"
              value={bypassUrl}
              onChange={(e) => setBypassUrl(e.target.value)}
              placeholder="https://example.com/admin"
              className="ltr-isolate flex-1 h-8 px-2.5 rounded bg-inset border border-border-subtle font-mono"
            />
            <button type="submit" className="h-8 px-3 rounded bg-elevated border border-border-strong font-semibold">
              Mutate
            </button>
          </form>
          {bypassOut && (
            <pre dir="ltr" className="ltr-isolate p-2.5 rounded bg-inset border border-border-subtle font-mono text-[11px] max-h-44 overflow-auto">
              {JSON.stringify(bypassOut.variations || bypassOut, null, 2)}
            </pre>
          )}
        </section>
      </div>
    </div>
  );
}
