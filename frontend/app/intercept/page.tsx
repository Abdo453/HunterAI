"use client";

import React, { useCallback, useEffect, useRef, useState } from "react";
import {
  Radar,
  Globe,
  FileSearch,
  KeyRound,
  Unlock,
  Send,
  RefreshCw,
  Loader2,
  Eye,
  X,
  Image as ImageIcon,
} from "lucide-react";
import {
  BrowserStatusResponse,
  BurpStatusResponse,
  BurpTrafficItem,
} from "@/lib/api-types";
import { usePlatform } from "@/lib/platform-context";
import { useI18n } from "@/lib/i18n";
import { sanitizePlainTerminalText } from "@/lib/terminal-sanitizer";

function LazyScreenshotCard({ src, alt, label }: { src: string; alt: string; label: string }) {
  const hostRef = useRef<HTMLDivElement | null>(null);
  const [visible, setVisible] = useState<boolean>(false);

  useEffect(() => {
    const el = hostRef.current;
    if (!el || typeof IntersectionObserver === "undefined") {
      setVisible(true);
      return;
    }
    const observer = new IntersectionObserver(
      (entries) => {
        if (entries.some((entry) => entry.isIntersecting)) {
          setVisible(true);
          observer.disconnect();
        }
      },
      { rootMargin: "120px" }
    );
    observer.observe(el);
    return () => observer.disconnect();
  }, []);

  return (
    <div ref={hostRef} className="rounded border border-border-subtle bg-inset overflow-hidden">
      <div className="px-2 py-1 text-[10px] font-mono text-ink-muted border-b border-border-subtle truncate ltr-isolate flex items-center gap-1">
        <ImageIcon className="w-3 h-3 text-sentinel-ai shrink-0" />
        <span className="truncate">{label}</span>
      </div>
      {visible ? (
        // eslint-disable-next-line @next/next/no-img-element
        <img
          src={src}
          alt={alt}
          loading="lazy"
          className="w-full h-36 object-cover bg-canvas"
        />
      ) : (
        <div className="w-full h-36 flex items-center justify-center text-[11px] font-mono text-ink-muted">
          ...
        </div>
      )}
    </div>
  );
}

export default function InterceptPage() {
  const { selectedEngagement, engagementSelectionSeq, targetDomain, sendToRepeater, apiJson } = usePlatform();
  const { t } = useI18n();

  const [burpStatus, setBurpStatus] = useState<BurpStatusResponse | null>(null);
  const [traffic, setTraffic] = useState<BurpTrafficItem[]>([]);
  const [selectedTx, setSelectedTx] = useState<BurpTrafficItem | null>(null);
  const [browserState, setBrowserState] = useState<BrowserStatusResponse | null>(null);
  const [browserChecked, setBrowserChecked] = useState<boolean>(false);

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

  const lastSyncedEngIdRef = useRef<string>("");
  const userEditedDomainRef = useRef<boolean>(false);
  const lastManualPickSeqRef = useRef<number>(engagementSelectionSeq);

  useEffect(() => {
    if (engagementSelectionSeq !== lastManualPickSeqRef.current) {
      lastManualPickSeqRef.current = engagementSelectionSeq;
      userEditedDomainRef.current = false;
      const engId = selectedEngagement?.id || "";
      lastSyncedEngIdRef.current = engId;
      if (selectedEngagement?.target) {
        setDorkDomain(selectedEngagement.target);
      }
      return;
    }

    const engId = selectedEngagement?.id || "";
    if (!engId) {
      lastSyncedEngIdRef.current = "";
      return;
    }
    if (engId !== lastSyncedEngIdRef.current) {
      lastSyncedEngIdRef.current = engId;
      if (selectedEngagement?.target && !userEditedDomainRef.current) {
        setDorkDomain(selectedEngagement.target);
      }
    }
  }, [selectedEngagement, engagementSelectionSeq]);

  const loadFeed = useCallback(async () => {
    const [stR, trR, brR] = await Promise.all([
      apiJson<BurpStatusResponse>("/api/burp/status"),
      apiJson<{ items?: BurpTrafficItem[]; traffic?: BurpTrafficItem[] }>("/api/burp/traffic?limit=50"),
      apiJson<BrowserStatusResponse>("/api/control/browser"),
    ]);
    if (stR.ok && stR.data) setBurpStatus(stR.data);
    if (trR.ok && trR.data) {
      const list = Array.isArray(trR.data.items)
        ? trR.data.items
        : Array.isArray(trR.data.traffic)
          ? trR.data.traffic
          : [];
      setTraffic(list);
    }
    if (brR.ok && brR.data) {
      setBrowserState(brR.data);
    }
    setBrowserChecked(true);
  }, [apiJson]);

  useEffect(() => {
    void loadFeed();
  }, [loadFeed]);

  const proxyOnline = Boolean(
    burpStatus?.proxy?.reachable ||
      burpStatus?.proxy?.online ||
      burpStatus?.proxy?.status === "online"
  );
  const agentOnline = Boolean(
    burpStatus?.agent?.reachable ||
      burpStatus?.agent?.online ||
      burpStatus?.agent?.status === "online"
  );

  const browserStatusLabel = !browserChecked
    ? t("states.checking")
    : browserState?.connection_status
      ? String(browserState.connection_status)
      : browserState?.playwright_available
        ? "READY"
        : "OFFLINE";
  const browserReady =
    browserState?.playwright_available === true ||
    browserStatusLabel.toUpperCase() === "READY" ||
    browserState?.status === "ready";

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
    userEditedDomainRef.current = true;
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

  // Extract safe image data URLs/paths if browser explore produced screenshots
  const browseScreenshots = React.useMemo(() => {
    if (!browseRes) return [];
    const list: Array<{ src: string; label: string }> = [];
    const rawArr = Array.isArray(browseRes.screenshots)
      ? browseRes.screenshots
      : Array.isArray(browseRes.pages)
        ? browseRes.pages
        : [];
    for (const entry of rawArr) {
      if (typeof entry === "string" && (entry.startsWith("data:image/") || entry.startsWith("/api/"))) {
        list.push({ src: entry, label: t("browser.screenshotLabel") });
      } else if (entry && typeof entry === "object") {
        const obj = entry as Record<string, unknown>;
        const src = String(obj.screenshot_data_url || obj.screenshot_url || obj.data_url || "");
        if (src.startsWith("data:image/") || src.startsWith("/api/")) {
          list.push({ src, label: String(obj.url || obj.title || t("browser.screenshotLabel")) });
        }
      }
    }
    return list;
  }, [browseRes, t]);

  const burpStatsEntries = Object.entries(burpStatus?.stats || {}).slice(0, 6);

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
                proxyOnline
                  ? "bg-sentinel-success/15 text-sentinel-success border-sentinel-success/35"
                  : "bg-sentinel-warning/15 text-sentinel-warning border-sentinel-warning/35"
              }`}
            >
              {t("burp.proxyPortLabel")} {burpStatus?.proxy?.port ?? 8080}:{" "}
              {proxyOnline ? t("status.connected") : t("status.offline")}
            </span>
            <span
              className={`px-2.5 py-1 rounded-full border ${
                agentOnline
                  ? "bg-sentinel-success/15 text-sentinel-success border-sentinel-success/35"
                  : "bg-elevated text-ink-muted border-border-subtle"
              }`}
            >
              {t("burp.agentPortLabel")} {burpStatus?.agent?.port ?? 8085}:{" "}
              {agentOnline ? t("status.connected") : t("status.standby")}
            </span>
            <button
              type="button"
              onClick={() => void loadFeed()}
              className="h-8 px-2.5 rounded border border-border-subtle bg-elevated hover:border-border-strong text-ink-primary flex items-center gap-1"
            >
              <RefreshCw className="w-3.5 h-3.5" />
              <span>{t("common.refresh")}</span>
            </button>
          </div>
        </div>

        {burpStatsEntries.length > 0 && (
          <div className="flex flex-wrap gap-2 text-[11px] font-mono">
            {burpStatsEntries.map(([k, v]) => (
              <span
                key={k}
                className="px-2 py-0.5 rounded bg-elevated border border-border-subtle text-ink-secondary ltr-isolate tabular-nums"
              >
                {k}: {typeof v === "object" ? JSON.stringify(v) : String(v)}
              </span>
            ))}
          </div>
        )}

        {traffic.length === 0 ? (
          <div className="py-6 text-center text-xs text-ink-muted">{t("studio.noTraffic")}</div>
        ) : (
          <div className="overflow-x-auto border border-border-subtle rounded-md bg-inset max-h-72 overflow-y-auto">
            <table className="w-full text-xs border-collapse">
              <thead className="bg-elevated border-b border-border-subtle text-ink-muted sticky top-0">
                <tr>
                  <th className="py-2 px-3 text-start">{t("common.timestamp")}</th>
                  <th className="py-2 px-3 text-start">{t("burp.colMethod")}</th>
                  <th className="py-2 px-3 text-start">{t("burp.colHost")}</th>
                  <th className="py-2 px-3 text-start">{t("burp.colPath")}</th>
                  <th className="py-2 px-3 text-start">{t("common.status")}</th>
                  <th className="py-2 px-3 text-start">{t("burp.colLength")}</th>
                  <th className="py-2 px-3 text-start">{t("common.actions")}</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border-subtle font-mono">
                {traffic.map((tx, idx) => {
                  const statusCode = tx.status || tx.response_status || 0;
                  const scheme = tx.scheme || "https";
                  return (
                    <tr
                      key={`${tx.id || tx.tx_id || `${tx.method}-${tx.host}${tx.path}`}-${idx}`}
                      className={`hover:bg-elevated/60 ltr-isolate ${selectedTx?.id === tx.id ? "bg-sentinel-primary/10" : ""}`}
                    >
                      <td className="py-1.5 px-3 text-ink-muted whitespace-nowrap">{tx.time}</td>
                      <td className="py-1.5 px-3 text-sentinel-primary font-semibold">{tx.method}</td>
                      <td className="py-1.5 px-3 text-ink-primary max-w-[160px] truncate">{tx.host}</td>
                      <td className="py-1.5 px-3 text-ink-secondary max-w-[220px] truncate">{tx.path}</td>
                      <td className="py-1.5 px-3 tabular-nums">{statusCode || "—"}</td>
                      <td className="py-1.5 px-3 tabular-nums text-ink-muted">{tx.length ?? 0}B</td>
                      <td className="py-1.5 px-3">
                        <div className="flex items-center gap-1.5">
                          <button
                            type="button"
                            onClick={() => setSelectedTx(tx)}
                            aria-label={`${t("common.details")} ${tx.method} ${tx.path}`}
                            className="px-2 py-0.5 rounded bg-elevated border border-border-subtle hover:border-border-strong text-ink-secondary hover:text-ink-primary flex items-center gap-1"
                          >
                            <Eye className="w-3 h-3" />
                            <span>{t("common.details")}</span>
                          </button>
                          <button
                            type="button"
                            onClick={() =>
                              sendToRepeater({
                                rawRequest: `${tx.method} ${tx.path} HTTP/1.1\nHost: ${tx.host}\nUser-Agent: HunterAI/2.0\n\n${tx.request_body_preview || ""}`,
                                targetUrl: tx.url || `${scheme}://${tx.host}${tx.path}`,
                              })
                            }
                            className="px-2 py-0.5 rounded bg-sentinel-primary/15 border border-sentinel-primary/40 text-sentinel-primary flex items-center gap-1"
                          >
                            <Send className="w-3 h-3 rtl:rotate-180" />
                            <span>{t("editor.tabRepeater")}</span>
                          </button>
                        </div>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}

        {/* Selected Transaction Inspector */}
        {selectedTx && (
          <div className="p-3 rounded-md bg-elevated border border-border-strong space-y-2 text-xs">
            <div className="flex items-center justify-between gap-2">
              <span className="font-mono font-semibold text-sentinel-primary ltr-isolate truncate">
                {selectedTx.method} {selectedTx.url || `${selectedTx.host}${selectedTx.path}`} ·{" "}
                {selectedTx.status || selectedTx.response_status}
              </span>
              <button
                type="button"
                onClick={() => setSelectedTx(null)}
                aria-label={t("common.close")}
                className="h-7 w-7 rounded border border-border-subtle bg-inset text-ink-secondary hover:text-ink-primary flex items-center justify-center"
              >
                <X className="w-3.5 h-3.5" />
              </button>
            </div>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-2.5">
              <div className="space-y-1">
                <div className="text-[11px] font-semibold text-ink-secondary">{t("burp.rawRequest")}</div>
                <pre dir="ltr" className="ltr-isolate p-2 rounded bg-inset border border-border-subtle font-mono text-[11px] text-ink-secondary max-h-40 overflow-auto whitespace-pre-wrap">
                  {sanitizePlainTerminalText(
                    `${selectedTx.method} ${selectedTx.path} HTTP/1.1\nHost: ${selectedTx.host}\n${
                      selectedTx.request_headers
                        ? Object.entries(selectedTx.request_headers)
                            .map(([k, v]) => `${k}: ${String(v)}`)
                            .join("\n")
                        : ""
                    }\n\n${selectedTx.request_body_preview || ""}`
                  )}
                </pre>
              </div>
              <div className="space-y-1">
                <div className="text-[11px] font-semibold text-ink-secondary">{t("burp.rawResponse")}</div>
                <pre dir="ltr" className="ltr-isolate p-2 rounded bg-inset border border-border-subtle font-mono text-[11px] text-ink-secondary max-h-40 overflow-auto whitespace-pre-wrap">
                  {sanitizePlainTerminalText(
                    `HTTP/1.1 ${selectedTx.status || selectedTx.response_status || 0}\n${
                      selectedTx.response_headers
                        ? Object.entries(selectedTx.response_headers)
                            .map(([k, v]) => `${k}: ${String(v)}`)
                            .join("\n")
                        : ""
                    }\n\n${selectedTx.response_body_preview || ""}`
                  )}
                </pre>
              </div>
            </div>
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
              aria-label={t("burp.pasteTrafficPlaceholder")}
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
                className="min-h-[44px] sm:min-h-[32px] px-3 rounded bg-sentinel-primary text-sentinel-onAccent font-semibold flex items-center gap-1.5"
              >
                {inspecting && <Loader2 className="w-3.5 h-3.5 animate-spin" />}
                <span>{t("burp.inspectLogs")}</span>
              </button>
            </div>
          </form>

          {inspectRes && (
            <pre dir="ltr" className="ltr-isolate p-3 rounded bg-inset border border-border-subtle font-mono text-[11px] max-h-48 overflow-auto">
              {sanitizePlainTerminalText(JSON.stringify(inspectRes, null, 2))}
            </pre>
          )}
        </section>

        <section className="lg:col-span-6 sentinel-surface p-4 space-y-3">
          <div className="flex items-center justify-between pb-2 border-b border-border-subtle">
            <div className="flex items-center gap-2">
              <Globe className="w-4 h-4 text-sentinel-ai" />
              <h2 className="text-sm font-semibold text-ink-primary">{t("browser.title")}</h2>
            </div>
            <span
              className={`text-xs font-mono px-2 py-0.5 rounded border ${
                browserReady
                  ? "bg-sentinel-success/15 text-sentinel-success border-sentinel-success/35"
                  : "bg-sentinel-warning/15 text-sentinel-warning border-sentinel-warning/35"
              }`}
            >
              {browserStatusLabel}
            </span>
          </div>

          <div className="text-xs font-mono text-ink-muted ltr-isolate">
            {String(browserState?.browser_type || "Chromium")}
            {browserState?.chrome_binary ? ` · ${browserState.chrome_binary}` : ""}
          </div>

          <form onSubmit={launchBrowserExplore} className="flex gap-2 text-xs">
            <input
              type="text"
              dir="ltr"
              value={browseUrl}
              onChange={(e) => setBrowseUrl(e.target.value)}
              placeholder={t("browser.exploreUrlPlaceholder")}
              aria-label={t("browser.exploreUrlPlaceholder")}
              className="ltr-isolate flex-1 h-9 px-3 rounded bg-inset border border-border-subtle font-mono"
            />
            <button
              type="submit"
              disabled={browsing}
              className="min-h-[44px] sm:min-h-[36px] px-3 rounded bg-sentinel-primary text-sentinel-onAccent font-semibold flex items-center gap-1.5"
            >
              {browsing && <Loader2 className="w-3.5 h-3.5 animate-spin" />}
              <span>{t("browser.launchExplore")}</span>
            </button>
          </form>

          {browseScreenshots.length > 0 && (
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
              {browseScreenshots.map((shot, idx) => (
                <LazyScreenshotCard
                  key={`${shot.label}-${idx}`}
                  src={shot.src}
                  alt={shot.label}
                  label={shot.label}
                />
              ))}
            </div>
          )}

          {browseRes && (
            <pre dir="ltr" className="ltr-isolate p-3 rounded bg-inset border border-border-subtle font-mono text-[11px] max-h-48 overflow-auto">
              {sanitizePlainTerminalText(JSON.stringify(browseRes, null, 2))}
            </pre>
          )}
        </section>
      </div>

      {/* Recon Tools: Dorks, JS Secret Miner, 403 Bypass */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-5">
        <section className="sentinel-surface p-4 space-y-3">
          <div className="flex items-center gap-2 pb-2 border-b border-border-subtle">
            <FileSearch className="w-4 h-4 text-sentinel-primary" />
            <h2 className="text-sm font-semibold text-ink-primary">{t("intercept.dorksTitle")}</h2>
          </div>
          <form onSubmit={fetchDorks} className="flex gap-2 text-xs">
            <input
              type="text"
              dir="ltr"
              value={dorkDomain}
              onChange={(e) => {
                userEditedDomainRef.current = true;
                setDorkDomain(e.target.value);
              }}
              placeholder="example.com"
              aria-label={t("intercept.dorksTitle")}
              className="ltr-isolate flex-1 h-8 px-2.5 rounded bg-inset border border-border-subtle font-mono"
            />
            <button type="submit" className="h-8 px-3 rounded bg-elevated border border-border-strong font-semibold">
              {t("intercept.generateBtn")}
            </button>
          </form>
          {dorksOut && (
            <pre dir="ltr" className="ltr-isolate p-2.5 rounded bg-inset border border-border-subtle font-mono text-[11px] max-h-44 overflow-auto">
              {sanitizePlainTerminalText(JSON.stringify(dorksOut, null, 2))}
            </pre>
          )}
        </section>

        <section className="sentinel-surface p-4 space-y-3">
          <div className="flex items-center gap-2 pb-2 border-b border-border-subtle">
            <KeyRound className="w-4 h-4 text-sentinel-danger" />
            <h2 className="text-sm font-semibold text-ink-primary">{t("intercept.jsMinerTitle")}</h2>
          </div>
          <form onSubmit={mineJs} className="space-y-2 text-xs">
            <textarea
              rows={3}
              dir="ltr"
              value={jsContent}
              onChange={(e) => setJsContent(e.target.value)}
              placeholder={t("intercept.jsMinerPlaceholder")}
              aria-label={t("intercept.jsMinerPlaceholder")}
              className="ltr-isolate w-full p-2 rounded bg-inset border border-border-subtle font-mono text-[11px]"
            />
            <button type="submit" className="h-8 px-3 rounded bg-elevated border border-border-strong font-semibold">
              {t("intercept.mineBtn")}
            </button>
          </form>
          {jsOut && (
            <pre dir="ltr" className="ltr-isolate p-2.5 rounded bg-inset border border-border-subtle font-mono text-[11px] max-h-36 overflow-auto">
              {sanitizePlainTerminalText(JSON.stringify(jsOut, null, 2))}
            </pre>
          )}
        </section>

        <section className="sentinel-surface p-4 space-y-3">
          <div className="flex items-center gap-2 pb-2 border-b border-border-subtle">
            <Unlock className="w-4 h-4 text-sentinel-warning" />
            <h2 className="text-sm font-semibold text-ink-primary">{t("intercept.bypass403Title")}</h2>
          </div>
          <form onSubmit={gen403Bypass} className="flex gap-2 text-xs">
            <input
              type="text"
              dir="ltr"
              value={bypassUrl}
              onChange={(e) => setBypassUrl(e.target.value)}
              placeholder="https://example.com/admin"
              aria-label={t("intercept.bypass403Title")}
              className="ltr-isolate flex-1 h-8 px-2.5 rounded bg-inset border border-border-subtle font-mono"
            />
            <button type="submit" className="h-8 px-3 rounded bg-elevated border border-border-strong font-semibold">
              {t("intercept.mutateBtn")}
            </button>
          </form>
          {bypassOut && (
            <pre dir="ltr" className="ltr-isolate p-2.5 rounded bg-inset border border-border-subtle font-mono text-[11px] max-h-44 overflow-auto">
              {sanitizePlainTerminalText(JSON.stringify(bypassOut.variations || bypassOut, null, 2))}
            </pre>
          )}
        </section>
      </div>
    </div>
  );
}
