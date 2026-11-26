"use client";

import React, { useCallback, useEffect, useState } from "react";
import { Database, Search, RefreshCw, ShieldCheck, Loader2, BarChart3 } from "lucide-react";
import {
  VulnIntelCoverageResponse,
  VulnIntelRecord,
  VulnIntelSearchResponse,
  VulnIntelSyncResponse,
  VulnIntelTriageResponse,
} from "@/lib/api-types";
import { usePlatform } from "@/lib/platform-context";
import { useI18n } from "@/lib/i18n";

export default function VulnIntelPanel() {
  const { apiJson, selectedEngagement } = usePlatform();
  const { t } = useI18n();

  const [activeTab, setActiveTab] = useState<"search" | "triage" | "coverage">("search");
  const [query, setQuery] = useState<string>("");
  const [severity, setSeverity] = useState<string>("");
  const [ecosystem, setEcosystem] = useState<string>("");
  const [results, setResults] = useState<VulnIntelRecord[]>([]);
  const [totalInDb, setTotalInDb] = useState<number>(0);
  const [dbStatus, setDbStatus] = useState<string>("");
  const [searching, setSearching] = useState<boolean>(false);

  const [coverage, setCoverage] = useState<VulnIntelCoverageResponse | null>(null);
  const [syncInfo, setSyncInfo] = useState<VulnIntelSyncResponse | null>(null);
  const [syncing, setSyncing] = useState<boolean>(false);

  const [triagePkg, setTriagePkg] = useState<string>("");
  const [triageEco, setTriageEco] = useState<string>("composer");
  const [triageRes, setTriageRes] = useState<VulnIntelTriageResponse | null>(null);
  const [triaging, setTriaging] = useState<boolean>(false);

  const loadInitial = useCallback(async () => {
    const [searchR, covR, syncR] = await Promise.all([
      apiJson<VulnIntelSearchResponse>("/api/vuln-intel/search?limit=25"),
      apiJson<VulnIntelCoverageResponse>("/api/vuln-intel/coverage?source=nvd"),
      apiJson<VulnIntelSyncResponse>("/api/vuln-intel/sync"),
    ]);
    if (searchR.ok && searchR.data) {
      setResults(Array.isArray(searchR.data.results) ? searchR.data.results : []);
      setTotalInDb(Number(searchR.data.total_in_db || 0));
      setDbStatus(String(searchR.data.status || ""));
    }
    if (covR.ok && covR.data) setCoverage(covR.data);
    if (syncR.ok && syncR.data) setSyncInfo(syncR.data);
  }, [apiJson]);

  useEffect(() => {
    void loadInitial();
  }, [loadInitial]);

  const handleSearch = async (e: React.FormEvent) => {
    e.preventDefault();
    setSearching(true);
    const params = new URLSearchParams({ limit: "30" });
    if (query.trim()) params.set("q", query.trim());
    if (severity) params.set("severity", severity);
    if (ecosystem.trim()) params.set("ecosystem", ecosystem.trim());
    const res = await apiJson<VulnIntelSearchResponse>(
      `/api/vuln-intel/search?${params.toString()}`
    );
    setSearching(false);
    if (res.ok && res.data) {
      setResults(Array.isArray(res.data.results) ? res.data.results : []);
      setTotalInDb(Number(res.data.total_in_db || 0));
      setDbStatus(String(res.data.status || ""));
    }
  };

  const handleSync = async (dryRun: boolean) => {
    setSyncing(true);
    const res = await apiJson<VulnIntelSyncResponse>("/api/vuln-intel/sync", {
      method: "POST",
      body: { source: "nvd", dry_run: dryRun, max_pages: 1 },
    });
    setSyncing(false);
    if (res.data) {
      setSyncInfo(res.data);
    }
    if (!dryRun) {
      await loadInitial();
    }
  };

  const handleTriage = async (e: React.FormEvent) => {
    e.preventDefault();
    setTriaging(true);
    const pkgList = triagePkg
      .split(",")
      .map((s) => s.trim())
      .filter(Boolean)
      .map((item) => {
        const [name, version] = item.split("@");
        return { name: name.trim(), version: (version || "").trim() || undefined };
      });
    const res = await apiJson<VulnIntelTriageResponse>("/api/vuln-intel/triage", {
      method: "POST",
      body: {
        target: selectedEngagement?.target || "workspace-project",
        ecosystem: triageEco,
        packages: pkgList,
        include_tool_selection: true,
      },
    });
    setTriaging(false);
    if (res.ok && res.data) {
      setTriageRes(res.data);
    }
  };

  return (
    <section
      data-testid="vuln-intel-panel"
      aria-labelledby="vuln-intel-heading"
      className="sentinel-surface p-4 space-y-3"
    >
      <div className="flex flex-wrap items-center justify-between gap-2 pb-2 border-b border-border-subtle">
        <div className="flex items-center gap-2 min-w-0">
          <Database className="w-4 h-4 text-sentinel-primary shrink-0" />
          <h2 id="vuln-intel-heading" className="text-sm font-semibold text-ink-primary truncate">
            {t("vulnIntel.title")}
          </h2>
          <span className="px-2 py-0.5 rounded-full text-[11px] font-mono tabular-nums bg-elevated border border-border-subtle text-ink-secondary">
            {totalInDb.toLocaleString()} {t("vulnIntel.advisoriesCount")}
          </span>
          {dbStatus === "UNAVAILABLE" && (
            <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-sentinel-warning/15 text-sentinel-warning border border-sentinel-warning/35">
              {t("vulnIntel.emptyDbBadge")}
            </span>
          )}
        </div>

        <div className="flex flex-wrap items-center gap-1.5">
          <div role="tablist" className="flex items-center gap-1 bg-inset p-1 rounded border border-border-subtle">
            {(
              [
                { id: "search", label: t("vulnIntel.tabSearch") },
                { id: "triage", label: t("vulnIntel.tabTriage") },
                { id: "coverage", label: t("vulnIntel.tabCoverage") },
              ] as const
            ).map((tab) => (
              <button
                key={tab.id}
                type="button"
                role="tab"
                aria-selected={activeTab === tab.id}
                onClick={() => setActiveTab(tab.id)}
                className={`px-2.5 py-1 rounded text-xs font-medium transition-colors ${
                  activeTab === tab.id
                    ? "bg-elevated text-sentinel-primary border border-border-subtle"
                    : "text-ink-muted hover:text-ink-primary"
                }`}
              >
                {tab.label}
              </button>
            ))}
          </div>

          <button
            type="button"
            disabled={syncing}
            onClick={() => void handleSync(true)}
            className="h-8 px-2.5 rounded border border-border-subtle bg-elevated hover:border-border-strong text-xs text-ink-primary flex items-center gap-1 disabled:opacity-50"
          >
            {syncing ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <RefreshCw className="w-3.5 h-3.5" />}
            <span>{t("vulnIntel.syncPreviewBtn")}</span>
          </button>
        </div>
      </div>

      {activeTab === "search" && (
        <div className="space-y-3">
          <form onSubmit={handleSearch} className="grid grid-cols-1 sm:grid-cols-12 gap-2 text-xs">
            <div className="sm:col-span-5 relative">
              <Search className="w-3.5 h-3.5 text-ink-muted absolute top-1/2 -translate-y-1/2 start-2.5 pointer-events-none" />
              <input
                type="search"
                value={query}
                onChange={(e) => setQuery(e.target.value)}
                placeholder={t("vulnIntel.searchPlaceholder")}
                aria-label={t("vulnIntel.searchPlaceholder")}
                className="w-full h-9 ps-8 pe-3 rounded bg-inset border border-border-subtle text-ink-primary placeholder:text-ink-muted"
              />
            </div>
            <select
              value={severity}
              onChange={(e) => setSeverity(e.target.value)}
              aria-label={t("common.severity")}
              className="sm:col-span-3 h-9 px-2.5 rounded bg-inset border border-border-subtle text-ink-primary"
            >
              <option value="">{t("common.all")}</option>
              <option value="CRITICAL">CRITICAL</option>
              <option value="HIGH">HIGH</option>
              <option value="MEDIUM">MEDIUM</option>
              <option value="LOW">LOW</option>
            </select>
            <input
              type="text"
              dir="ltr"
              value={ecosystem}
              onChange={(e) => setEcosystem(e.target.value)}
              placeholder={t("vulnIntel.ecosystemPlaceholder")}
              aria-label={t("vulnIntel.ecosystemPlaceholder")}
              className="sm:col-span-2 ltr-isolate h-9 px-2.5 rounded bg-inset border border-border-subtle font-mono text-ink-primary"
            />
            <button
              type="submit"
              disabled={searching}
              className="sm:col-span-2 h-9 px-3 rounded bg-sentinel-primary text-sentinel-onAccent font-semibold flex items-center justify-center gap-1.5 disabled:opacity-50"
            >
              {searching && <Loader2 className="w-3.5 h-3.5 animate-spin" />}
              <span>{t("common.search")}</span>
            </button>
          </form>

          {results.length === 0 ? (
            <div className="py-6 text-center text-xs text-ink-muted">
              {totalInDb === 0 ? t("vulnIntel.emptyDbHint") : t("vulnIntel.noMatches")}
            </div>
          ) : (
            <div className="space-y-2 max-h-64 overflow-y-auto pe-1">
              {results.map((rec, idx) => (
                <div
                  key={`${rec.id || "adv"}-${idx}`}
                  className="p-2.5 rounded bg-elevated border border-border-subtle text-xs space-y-1"
                >
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <span className="font-mono font-semibold text-sentinel-primary ltr-isolate">
                      {rec.id}
                    </span>
                    <div className="flex items-center gap-1.5 font-mono text-[11px]">
                      {rec.severity && (
                        <span className="px-1.5 py-0.5 rounded bg-sentinel-warning/15 text-sentinel-warning border border-sentinel-warning/35">
                          {rec.severity}
                        </span>
                      )}
                      {typeof rec.cvss_score === "number" && (
                        <span className="tabular-nums text-ink-secondary">
                          CVSS {rec.cvss_score.toFixed(1)}
                        </span>
                      )}
                    </div>
                  </div>
                  <p className="text-ink-secondary line-clamp-2">
                    {rec.title || rec.summary || rec.description || "—"}
                  </p>
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {activeTab === "triage" && (
        <div className="space-y-3 text-xs">
          <form onSubmit={handleTriage} className="grid grid-cols-1 sm:grid-cols-12 gap-2">
            <select
              value={triageEco}
              onChange={(e) => setTriageEco(e.target.value)}
              aria-label={t("vulnIntel.ecosystemPlaceholder")}
              className="sm:col-span-3 h-9 px-2.5 rounded bg-inset border border-border-subtle font-mono text-ink-primary"
            >
              <option value="composer">composer</option>
              <option value="npm">npm</option>
              <option value="pypi">pypi</option>
              <option value="go">go</option>
            </select>
            <input
              type="text"
              dir="ltr"
              value={triagePkg}
              onChange={(e) => setTriagePkg(e.target.value)}
              placeholder={t("vulnIntel.packagesPlaceholder")}
              aria-label={t("vulnIntel.packagesPlaceholder")}
              className="sm:col-span-7 ltr-isolate h-9 px-3 rounded bg-inset border border-border-subtle font-mono text-ink-primary"
            />
            <button
              type="submit"
              disabled={triaging}
              className="sm:col-span-2 h-9 px-3 rounded bg-sentinel-primary text-sentinel-onAccent font-semibold flex items-center justify-center gap-1.5 disabled:opacity-50"
            >
              {triaging ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <ShieldCheck className="w-3.5 h-3.5" />}
              <span>{t("vulnIntel.runTriageBtn")}</span>
            </button>
          </form>

          {triageRes && (
            <div className="p-3 rounded bg-inset border border-border-subtle space-y-2">
              <div className="flex items-center justify-between font-mono text-[11px] text-ink-muted">
                <span>
                  {t("vulnIntel.triageStatus")}: {triageRes.status}
                </span>
                <span className="tabular-nums">{triageRes.count}</span>
              </div>
              {triageRes.results.length === 0 ? (
                <div className="text-ink-muted">{t("vulnIntel.noMatches")}</div>
              ) : (
                <div className="space-y-1.5 max-h-48 overflow-y-auto">
                  {triageRes.results.slice(0, 20).map((r, idx) => (
                    <div
                      key={`${r.vuln_id || r.id || "tr"}-${idx}`}
                      className="p-2 rounded bg-elevated border border-border-subtle flex items-center justify-between gap-2"
                    >
                      <span className="font-mono text-ink-primary ltr-isolate">
                        {r.vuln_id || r.id}
                      </span>
                      <span className="font-mono text-[11px] text-sentinel-primary">
                        {r.verdict || r.status || (r.applicable ? "APPLICABLE" : "NOT_APPLICABLE")}
                      </span>
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}
        </div>
      )}

      {activeTab === "coverage" && (
        <div className="space-y-2.5 text-xs">
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-2.5">
            <div className="p-2.5 rounded bg-inset border border-border-subtle">
              <div className="text-ink-muted">{t("vulnIntel.storedRecords")}</div>
              <div className="font-mono font-bold text-base tabular-nums text-ink-primary">
                {Number(coverage?.stored_count ?? totalInDb).toLocaleString()}
              </div>
            </div>
            <div className="p-2.5 rounded bg-inset border border-border-subtle">
              <div className="text-ink-muted">{t("vulnIntel.completenessLabel")}</div>
              <div className="font-mono font-bold text-base text-sentinel-primary">
                {coverage?.completeness || t("states.unavailable")}
              </div>
            </div>
            <div className="p-2.5 rounded bg-inset border border-border-subtle">
              <div className="text-ink-muted">{t("vulnIntel.schemaVersion")}</div>
              <div className="font-mono font-bold text-base tabular-nums text-ink-secondary">
                v{syncInfo?.schema_version ?? 1}
              </div>
            </div>
          </div>

          <div className="flex flex-wrap items-center justify-between gap-2 p-2.5 rounded bg-inset border border-border-subtle">
            <div className="flex items-center gap-1.5 text-ink-secondary">
              <BarChart3 className="w-4 h-4 text-sentinel-ai" />
              <span>{t("vulnIntel.syncNote")}</span>
            </div>
            <button
              type="button"
              disabled={syncing}
              onClick={() => void handleSync(false)}
              className="h-8 px-3 rounded border border-sentinel-primary/40 bg-sentinel-primary/15 text-sentinel-primary font-semibold hover:opacity-90 disabled:opacity-50"
            >
              {t("vulnIntel.syncNowBtn")}
            </button>
          </div>
        </div>
      )}
    </section>
  );
}
