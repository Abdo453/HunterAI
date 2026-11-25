"use client";

import React, { useCallback, useEffect, useMemo, useState } from "react";
import {
  ReactFlow,
  Background,
  BackgroundVariant,
  Controls,
  MiniMap,
  Position,
  type Edge,
  type Node,
  type NodeMouseHandler,
} from "@xyflow/react";
import {
  Network,
  Table2,
  Database,
  Search,
  ExternalLink,
  X,
  Copy,
  Check,
  ChevronLeft,
  ChevronRight,
} from "lucide-react";
import { AssetRecord, usePlatform } from "@/lib/platform-context";
import { useTheme } from "@/lib/theme";
import { useI18n } from "@/lib/i18n";
import { safeHref } from "@/lib/sanitize";

const DEFAULT_CLUSTER_WINDOW = 8;
const TABLE_PAGE_SIZE = 10;

interface AssetNodeData extends Record<string, unknown> {
  label: string;
  nodeType: "root" | "cluster" | "asset";
  kind?: string;
  asset?: AssetRecord;
  expanded?: boolean;
  totalInCluster?: number;
}

type TopologyNode = Node<AssetNodeData>;

function getKindColor(kind: string): string {
  switch (kind.toUpperCase()) {
    case "SUBDOMAIN":
      return "var(--accent-primary)";
    case "ENDPOINT":
    case "API":
      return "var(--accent-success)";
    case "PORT":
    case "IP":
      return "var(--accent-warning)";
    case "TECH":
      return "var(--accent-ai)";
    default:
      return "var(--border-strong)";
  }
}

export default function AssetDualGraph() {
  const { assets, targetDomain, selectedEngagement, inspectedAsset, setInspectedAsset } =
    usePlatform();
  const { theme } = useTheme();
  const { t } = useI18n();

  const [viewMode, setViewMode] = useState<"graph" | "table">("graph");
  const [searchQuery, setSearchQuery] = useState<string>("");
  const [kindFilter, setKindFilter] = useState<string>("ALL");
  const [expandedClusters, setExpandedClusters] = useState<Record<string, boolean>>({});
  const [page, setPage] = useState<number>(1);
  const [copiedId, setCopiedId] = useState<string | null>(null);

  const rootTarget = selectedEngagement?.target || targetDomain || "target";

  useEffect(() => {
    if (!inspectedAsset) return;
    const onKeyDown = (ev: KeyboardEvent) => {
      if (ev.key === "Escape") {
        setInspectedAsset(null);
      }
    };
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, [inspectedAsset, setInspectedAsset]);

  const kindsList = useMemo(() => {
    const counts = new Map<string, number>();
    for (const a of assets) {
      const k = (a.kind || "ASSET").toUpperCase();
      counts.set(k, (counts.get(k) || 0) + 1);
    }
    return Array.from(counts.entries()).sort((a, b) => b[1] - a[1]);
  }, [assets]);

  const filteredAssets = useMemo(() => {
    const q = searchQuery.trim().toLowerCase();
    return assets.filter((a) => {
      const kindUpper = (a.kind || "ASSET").toUpperCase();
      if (kindFilter !== "ALL" && kindUpper !== kindFilter) {
        return false;
      }
      if (!q) return true;
      const title = typeof a.attributes?.title === "string" ? a.attributes.title : "";
      const liveUrl = typeof a.attributes?.live_url === "string" ? a.attributes.live_url : "";
      const tech = Array.isArray(a.attributes?.tech) ? a.attributes.tech.join(" ") : "";
      return (
        a.value.toLowerCase().includes(q) ||
        kindUpper.toLowerCase().includes(q) ||
        title.toLowerCase().includes(q) ||
        liveUrl.toLowerCase().includes(q) ||
        tech.toLowerCase().includes(q)
      );
    });
  }, [assets, kindFilter, searchQuery]);

  // Reset pagination cleanly when filters change
  useEffect(() => {
    setPage(1);
  }, [kindFilter, searchQuery, assets.length]);

  const totalPages = Math.max(1, Math.ceil(filteredAssets.length / TABLE_PAGE_SIZE));
  const safePage = Math.min(page, totalPages);
  const pagedAssets = useMemo(() => {
    const start = (safePage - 1) * TABLE_PAGE_SIZE;
    return filteredAssets.slice(start, start + TABLE_PAGE_SIZE);
  }, [filteredAssets, safePage]);

  // Build hierarchical React Flow graph: Root Target -> Asset Kind Clusters -> Assets/Endpoints
  const { nodes, edges, shownCount } = useMemo(() => {
    const grouped = new Map<string, AssetRecord[]>();
    for (const a of filteredAssets) {
      const k = (a.kind || "ASSET").toUpperCase();
      const bucket = grouped.get(k) || [];
      bucket.push(a);
      grouped.set(k, bucket);
    }

    const clusters = Array.from(grouped.entries());
    const builtNodes: TopologyNode[] = [];
    const builtEdges: Edge[] = [];

    if (clusters.length === 0) {
      return { nodes: builtNodes, edges: builtEdges, shownCount: 0 };
    }

    const rootId = "root-target";
    let currentY = 20;
    let totalRenderedLeaves = 0;

    const clusterPositions: number[] = [];

    for (const [kind, items] of clusters) {
      const isExpanded = Boolean(expandedClusters[kind]);
      const cap = isExpanded ? items.length : Math.min(items.length, DEFAULT_CLUSTER_WINDOW);
      const visibleItems = items.slice(0, cap);
      totalRenderedLeaves += visibleItems.length;

      const blockHeight = Math.max(1, visibleItems.length) * 62;
      const clusterY = currentY + Math.max(0, (blockHeight - 62) / 2);
      clusterPositions.push(clusterY);

      const clusterId = `cluster:${kind}`;
      const kindAccent = getKindColor(kind);

      const hiddenRemainder = items.length - visibleItems.length;
      const clusterLabel =
        hiddenRemainder > 0
          ? `${kind} (${visibleItems.length}/${items.length}) · +${hiddenRemainder}`
          : `${kind} (${items.length})`;

      builtNodes.push({
        id: clusterId,
        position: { x: 260, y: clusterY },
        sourcePosition: Position.Right,
        targetPosition: Position.Left,
        data: {
          label: clusterLabel,
          nodeType: "cluster",
          kind,
          expanded: isExpanded,
          totalInCluster: items.length,
        },
        style: {
          background: "var(--bg-elevated)",
          color: "var(--text-primary)",
          border: `1px solid ${kindAccent}`,
          borderRadius: "8px",
          fontFamily: "var(--font-mono)",
          fontSize: "11px",
          fontWeight: 600,
          padding: "8px 12px",
          width: 210,
          cursor: items.length > DEFAULT_CLUSTER_WINDOW ? "pointer" : "default",
        },
      });

      builtEdges.push({
        id: `edge:${rootId}->${clusterId}`,
        source: rootId,
        target: clusterId,
        style: { stroke: "var(--border-strong)", strokeWidth: 1.5 },
      });

      visibleItems.forEach((asset, idx) => {
        const leafId = `asset:${asset.id || `${kind}-${idx}`}`;
        const statusCode = asset.attributes?.status_code;
        const badge = statusCode ? ` [${String(statusCode)}]` : "";
        const shortVal =
          asset.value.length > 34 ? `${asset.value.slice(0, 31)}...` : asset.value;

        builtNodes.push({
          id: leafId,
          position: { x: 540, y: currentY + idx * 62 },
          targetPosition: Position.Left,
          data: {
            label: `${shortVal}${badge}`,
            nodeType: "asset",
            kind,
            asset,
          },
          style: {
            background: "var(--bg-surface)",
            color: statusCode ? "var(--accent-success)" : "var(--text-primary)",
            border: `1px solid ${
              statusCode ? "var(--accent-success)" : "var(--border-subtle)"
            }`,
            borderRadius: "6px",
            fontFamily: "var(--font-mono)",
            fontSize: "11px",
            padding: "7px 10px",
            width: 260,
            cursor: "pointer",
          },
        });

        builtEdges.push({
          id: `edge:${clusterId}->${leafId}`,
          source: clusterId,
          target: leafId,
          style: { stroke: "var(--border-subtle)", strokeWidth: 1.25 },
        });
      });

      currentY += blockHeight + 24;
    }

    const midY =
      clusterPositions.length > 0
        ? (clusterPositions[0] + clusterPositions[clusterPositions.length - 1]) / 2
        : 60;

    builtNodes.unshift({
      id: rootId,
      position: { x: 16, y: midY },
      sourcePosition: Position.Right,
      data: {
        label: rootTarget,
        nodeType: "root",
      },
      style: {
        background: "var(--accent-primary-bg)",
        color: "var(--accent-primary)",
        border: "1px solid var(--accent-primary)",
        borderRadius: "8px",
        fontFamily: "var(--font-mono)",
        fontSize: "12px",
        fontWeight: 700,
        padding: "10px 14px",
        width: 190,
      },
    });

    return { nodes: builtNodes, edges: builtEdges, shownCount: totalRenderedLeaves };
  }, [filteredAssets, expandedClusters, rootTarget]);

  const handleNodeClick: NodeMouseHandler<TopologyNode> = useCallback(
    (_event, node) => {
      if (node.data.nodeType === "asset" && node.data.asset) {
        setInspectedAsset(node.data.asset);
      } else if (
        node.data.nodeType === "cluster" &&
        node.data.kind &&
        (node.data.totalInCluster || 0) > DEFAULT_CLUSTER_WINDOW
      ) {
        const k = node.data.kind;
        setExpandedClusters((prev) => ({ ...prev, [k]: !prev[k] }));
      }
    },
    [setInspectedAsset]
  );

  const handleCopyJson = async (text: string, key: string) => {
    try {
      await navigator.clipboard.writeText(text);
      setCopiedId(key);
      window.setTimeout(() => setCopiedId(null), 1500);
    } catch {
      // Ignore clipboard failures
    }
  };

  const inspectedLiveUrl = inspectedAsset
    ? safeHref(inspectedAsset.attributes?.live_url, "#")
    : "#";

  return (
    <section
      aria-labelledby="asset-graph-heading"
      className="sentinel-surface p-4 flex flex-col gap-3 h-[540px]"
    >
      {/* Header */}
      <div className="flex flex-wrap items-center justify-between gap-2 pb-3 border-b border-border-subtle">
        <div className="flex items-center gap-2 min-w-0">
          <Network className="w-4 h-4 text-sentinel-primary shrink-0" />
          <h2 id="asset-graph-heading" className="text-sm font-semibold text-ink-primary truncate">
            {t("graph.title")}
          </h2>
          <span className="text-xs font-mono tabular-nums px-2 py-0.5 rounded bg-elevated border border-border-subtle text-ink-secondary">
            {filteredAssets.length}
          </span>
        </div>

        <div
          role="tablist"
          aria-label="Asset display mode"
          className="flex items-center gap-1 bg-inset p-1 rounded-md border border-border-subtle"
        >
          <button
            type="button"
            role="tab"
            aria-selected={viewMode === "graph"}
            onClick={() => setViewMode("graph")}
            className={`px-2.5 py-1 rounded text-xs font-medium flex items-center gap-1.5 transition-colors ${
              viewMode === "graph"
                ? "bg-elevated text-ink-primary border border-border-subtle"
                : "text-ink-muted hover:text-ink-primary"
            }`}
          >
            <Network className="w-3.5 h-3.5 text-sentinel-primary" />
            <span>{t("graph.topologyView")}</span>
          </button>

          <button
            type="button"
            role="tab"
            aria-selected={viewMode === "table"}
            onClick={() => setViewMode("table")}
            className={`px-2.5 py-1 rounded text-xs font-medium flex items-center gap-1.5 transition-colors ${
              viewMode === "table"
                ? "bg-elevated text-ink-primary border border-border-subtle"
                : "text-ink-muted hover:text-ink-primary"
            }`}
          >
            <Table2 className="w-3.5 h-3.5 text-sentinel-primary" />
            <span>{t("graph.tableView")}</span>
          </button>
        </div>
      </div>

      {/* Filters */}
      <div className="flex flex-wrap items-center gap-2">
        <div className="relative flex-1 min-w-[190px]">
          <Search className="w-3.5 h-3.5 text-ink-muted absolute top-1/2 -translate-y-1/2 start-2.5 pointer-events-none" />
          <input
            type="search"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder={t("graph.searchPlaceholder")}
            aria-label={t("graph.searchPlaceholder")}
            className="w-full h-8 ps-8 pe-3 rounded bg-inset border border-border-subtle text-xs text-ink-primary placeholder:text-ink-muted"
          />
        </div>

        <div className="flex flex-wrap items-center gap-1">
          <button
            type="button"
            onClick={() => setKindFilter("ALL")}
            aria-pressed={kindFilter === "ALL"}
            className={`px-2 py-1 rounded text-[11px] font-mono tabular-nums border transition-colors ${
              kindFilter === "ALL"
                ? "border-sentinel-primary bg-[var(--accent-primary-bg)] text-sentinel-primary"
                : "border-border-subtle bg-elevated text-ink-muted hover:text-ink-primary"
            }`}
          >
            {t("graph.allKinds")} ({assets.length})
          </button>

          {kindsList.map(([kind, count]) => (
            <button
              key={kind}
              type="button"
              onClick={() => setKindFilter(kind)}
              aria-pressed={kindFilter === kind}
              className={`px-2 py-1 rounded text-[11px] font-mono tabular-nums border transition-colors ${
                kindFilter === kind
                  ? "border-sentinel-primary bg-[var(--accent-primary-bg)] text-sentinel-primary"
                  : "border-border-subtle bg-elevated text-ink-muted hover:text-ink-primary"
              }`}
            >
              {kind} ({count})
            </button>
          ))}
        </div>
      </div>

      {/* Main Content */}
      {filteredAssets.length === 0 ? (
        <div className="flex-1 flex flex-col items-center justify-center text-ink-muted text-center px-4">
          <Database className="w-9 h-9 mb-2 text-sentinel-primary opacity-50" />
          <p className="text-sm font-medium text-ink-secondary">{t("graph.emptyTitle")}</p>
          <p className="text-xs text-ink-muted mt-1">{t("graph.emptySub")}</p>
        </div>
      ) : viewMode === "graph" ? (
        <div className="flex-1 flex flex-col gap-2 min-h-0">
          <div className="flex items-center justify-between text-[11px] font-mono text-ink-muted px-0.5">
            <span>
              {t("graph.rootLabel")}: <strong className="text-ink-primary ltr-isolate">{rootTarget}</strong>
            </span>
            <span className="tabular-nums">
              {t("graph.showingWindow", { shown: shownCount, total: filteredAssets.length })}
            </span>
          </div>

          <div
            dir="ltr"
            className="ltr-isolate sentinel-flow flex-1 min-h-0 rounded-md border border-border-subtle bg-inset overflow-hidden"
          >
            <ReactFlow
              nodes={nodes}
              edges={edges}
              onNodeClick={handleNodeClick}
              colorMode={theme}
              nodesDraggable={false}
              nodesConnectable={false}
              fitView
              fitViewOptions={{ padding: 0.2 }}
              minZoom={0.35}
              maxZoom={1.75}
            >
              <Background
                variant={BackgroundVariant.Dots}
                gap={18}
                size={1}
                color={theme === "dark" ? "#334155" : "#cbd5e1"}
              />
              <Controls showInteractive={false} />
              <MiniMap
                pannable
                zoomable
                nodeColor={(node) => {
                  const data = node.data as AssetNodeData;
                  if (data.nodeType === "root") return theme === "dark" ? "#38bdf8" : "#0369a1";
                  if (data.nodeType === "cluster") return theme === "dark" ? "#a78bfa" : "#6d28d9";
                  return theme === "dark" ? "#34d399" : "#047857";
                }}
                maskColor={theme === "dark" ? "rgba(11, 15, 23, 0.72)" : "rgba(248, 250, 252, 0.75)"}
              />
            </ReactFlow>
          </div>
        </div>
      ) : (
        <div className="flex-1 flex flex-col min-h-0 gap-2">
          <div className="flex-1 overflow-auto border border-border-subtle rounded-md bg-inset">
            <table className="w-full text-xs border-collapse">
              <thead className="bg-elevated border-b border-border-subtle sticky top-0 z-10 text-ink-muted">
                <tr>
                  <th className="py-2 px-3 text-start font-semibold">{t("graph.colKind")}</th>
                  <th className="py-2 px-3 text-start font-semibold">{t("graph.colValue")}</th>
                  <th className="py-2 px-3 text-start font-semibold">{t("graph.colStatus")}</th>
                  <th className="py-2 px-3 text-start font-semibold">{t("graph.colTitle")}</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border-subtle">
                {pagedAssets.map((asset, idx) => {
                  const statusCode = asset.attributes?.status_code;
                  const title = typeof asset.attributes?.title === "string" ? asset.attributes.title : "";
                  const tech = Array.isArray(asset.attributes?.tech)
                    ? asset.attributes.tech.slice(0, 2).join(", ")
                    : "";

                  return (
                    <tr
                      key={asset.id || `${asset.value}-${idx}`}
                      tabIndex={0}
                      role="button"
                      onClick={() => setInspectedAsset(asset)}
                      onKeyDown={(e) => {
                        if (e.key === "Enter" || e.key === " ") {
                          e.preventDefault();
                          setInspectedAsset(asset);
                        }
                      }}
                      className="hover:bg-elevated/80 cursor-pointer transition-colors"
                    >
                      <td className="py-2 px-3 font-mono text-[11px] text-sentinel-primary whitespace-nowrap">
                        {asset.kind}
                      </td>
                      <td className="py-2 px-3 font-mono text-ink-primary ltr-isolate max-w-[260px] truncate">
                        {asset.value}
                      </td>
                      <td className="py-2 px-3 font-mono tabular-nums ltr-isolate whitespace-nowrap">
                        {statusCode ? (
                          <span className="px-1.5 py-0.5 rounded bg-[var(--accent-success-bg)] text-sentinel-success border border-[var(--accent-success)]/30">
                            {String(statusCode)}
                          </span>
                        ) : (
                          <span className="px-1.5 py-0.5 rounded bg-elevated text-ink-muted border border-border-subtle">
                            —
                          </span>
                        )}
                      </td>
                      <td className="py-2 px-3 text-ink-secondary max-w-[200px] truncate">
                        {title || tech || "—"}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>

          <div className="flex items-center justify-between text-xs text-ink-muted pt-1">
            <span className="font-mono tabular-nums">
              {t("graph.pageOf", { page: safePage, total: totalPages })}
            </span>
            <div className="flex items-center gap-1.5">
              <button
                type="button"
                disabled={safePage <= 1}
                onClick={() => setPage((p) => Math.max(1, p - 1))}
                className="h-7 px-2.5 rounded border border-border-subtle bg-elevated text-ink-primary disabled:opacity-40 flex items-center gap-1"
              >
                <ChevronLeft className="w-3.5 h-3.5" />
                <span>{t("graph.prevPage")}</span>
              </button>
              <button
                type="button"
                disabled={safePage >= totalPages}
                onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
                className="h-7 px-2.5 rounded border border-border-subtle bg-elevated text-ink-primary disabled:opacity-40 flex items-center gap-1"
              >
                <span>{t("graph.nextPage")}</span>
                <ChevronRight className="w-3.5 h-3.5" />
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Keyboard-Accessible Asset Inspector Drawer */}
      {inspectedAsset && (
        <div
          className="fixed inset-0 z-50 flex justify-end bg-black/50 backdrop-blur-[1px]"
          onClick={() => setInspectedAsset(null)}
        >
          <div
            role="dialog"
            aria-modal="true"
            aria-labelledby="asset-inspector-title"
            className="w-full max-w-lg h-full bg-surface border-s border-border-subtle shadow-sentinelMd flex flex-col overflow-hidden"
            onClick={(e) => e.stopPropagation()}
          >
            <div className="px-5 py-4 border-b border-border-subtle flex items-start justify-between gap-3">
              <div className="min-w-0 space-y-1">
                <div className="flex items-center gap-2">
                  <span className="text-xs font-mono px-2 py-0.5 rounded bg-[var(--accent-primary-bg)] text-sentinel-primary border border-[var(--accent-primary)]/30">
                    {inspectedAsset.kind}
                  </span>
                  {inspectedAsset.attributes?.status_code !== undefined && (
                    <span className="text-xs font-mono tabular-nums px-2 py-0.5 rounded bg-[var(--accent-success-bg)] text-sentinel-success border border-[var(--accent-success)]/30 ltr-isolate">
                      HTTP {String(inspectedAsset.attributes.status_code)}
                    </span>
                  )}
                </div>
                <h3
                  id="asset-inspector-title"
                  className="text-sm font-mono font-semibold text-ink-primary ltr-isolate break-all"
                >
                  {inspectedAsset.value}
                </h3>
              </div>

              <button
                type="button"
                onClick={() => setInspectedAsset(null)}
                aria-label={t("common.close")}
                className="h-8 w-8 rounded border border-border-subtle bg-elevated text-ink-secondary hover:text-ink-primary flex items-center justify-center shrink-0"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <div className="flex-1 overflow-y-auto p-5 space-y-4">
              <div className="flex flex-wrap items-center gap-2">
                <button
                  type="button"
                  onClick={() => void handleCopyJson(inspectedAsset.value, "val")}
                  className="h-8 px-3 rounded border border-border-subtle bg-elevated hover:border-border-strong text-xs text-ink-primary flex items-center gap-1.5"
                >
                  {copiedId === "val" ? <Check className="w-3.5 h-3.5 text-sentinel-success" /> : <Copy className="w-3.5 h-3.5" />}
                  <span>{copiedId === "val" ? t("common.copied") : t("common.copy")}</span>
                </button>

                {inspectedLiveUrl !== "#" && (
                  <a
                    href={inspectedLiveUrl}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="h-8 px-3 rounded border border-[var(--accent-primary)]/40 bg-[var(--accent-primary-bg)] text-sentinel-primary text-xs font-medium flex items-center gap-1.5"
                  >
                    <span>{t("graph.openUrl")}</span>
                    <ExternalLink className="w-3.5 h-3.5" />
                  </a>
                )}
              </div>

              <div className="space-y-1.5">
                <div className="flex items-center justify-between text-xs text-ink-muted">
                  <span className="font-semibold uppercase tracking-wider">
                    {t("graph.attributesJson")}
                  </span>
                  <button
                    type="button"
                    onClick={() =>
                      void handleCopyJson(
                        JSON.stringify(inspectedAsset.attributes || {}, null, 2),
                        "json"
                      )
                    }
                    className="text-sentinel-primary hover:underline flex items-center gap-1"
                  >
                    {copiedId === "json" ? <Check className="w-3 h-3" /> : <Copy className="w-3 h-3" />}
                    <span>{copiedId === "json" ? t("common.copied") : t("common.copy")}</span>
                  </button>
                </div>

                {Object.keys(inspectedAsset.attributes || {}).length === 0 ? (
                  <div className="p-3 rounded-md bg-elevated border border-border-subtle text-xs text-ink-muted">
                    {t("graph.noAttributes")}
                  </div>
                ) : (
                  <pre
                    dir="ltr"
                    className="ltr-isolate p-3.5 rounded-md bg-inset border border-border-subtle font-mono text-xs text-ink-secondary overflow-x-auto leading-relaxed"
                  >
                    {JSON.stringify(inspectedAsset.attributes, null, 2)}
                  </pre>
                )}
              </div>
            </div>
          </div>
        </div>
      )}
    </section>
  );
}
