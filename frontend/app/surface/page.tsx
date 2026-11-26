"use client";

import React, { useCallback, useEffect, useState } from "react";
import {
  Activity,
  GitCompare,
  Radio,
  RefreshCw,
  Sparkles,
  Users,
  Network,
} from "lucide-react";
import AssetDualGraph from "@/components/AssetDualGraph";
import { usePlatform } from "@/lib/platform-context";
import { useI18n } from "@/lib/i18n";

interface SwarmRosterItem {
  agent: string;
  role: string;
  status: string;
  node: string;
  active_tool: string;
}

interface WiretapEvent {
  id: string;
  time: string;
  from_agent: string;
  to_agent: string;
  type: string;
  summary: string;
  simulated?: boolean;
}

interface TwoBrainDiffItem {
  diff_id: string;
  title: string;
  target: string;
  vuln_class: string;
  confidence_score: number;
  brain_a_hypothesis: string;
  brain_b_verification: string;
  verdict?: string;
}

interface AttackGraphNode {
  id?: string;
  node_id?: string;
  label?: string;
  name?: string;
  node_type?: string;
  risk_score?: number;
}

interface AttackGraphEdge {
  id?: string;
  edge_id?: string;
  source?: string;
  source_node_id?: string;
  target?: string;
  target_node_id?: string;
  label?: string;
  relation_type?: string;
}

interface AttackGraphSnapshot {
  target?: string;
  nodes?: AttackGraphNode[] | Record<string, AttackGraphNode>;
  edges?: AttackGraphEdge[] | Record<string, AttackGraphEdge>;
}

function coerceGraphArray<T>(raw: unknown): T[] {
  if (Array.isArray(raw)) {
    return raw as T[];
  }
  if (raw && typeof raw === "object") {
    return Object.values(raw as Record<string, T>);
  }
  return [];
}

interface SwarmTelemetryPayload {
  target?: string | null;
  swarm_status?: string;
  active_runs_count?: number;
  graph?: { nodes?: unknown[]; edges?: unknown[]; nodes_count?: number };
  wiretap_events?: WiretapEvent[];
  two_brain_diffs?: TwoBrainDiffItem[];
  swarm_roster?: SwarmRosterItem[];
}

export default function SurfacePage() {
  const { targetDomain, selectedEngagement, apiJson } = usePlatform();
  const { t } = useI18n();

  const [telemetry, setTelemetry] = useState<SwarmTelemetryPayload | null>(null);
  const [causalGraph, setCausalGraph] = useState<AttackGraphSnapshot | null>(null);
  const [selectedDiff, setSelectedDiff] = useState<TwoBrainDiffItem | null>(null);

  const [baseStatus, setBaseStatus] = useState<number>(200);
  const [baseBody, setBaseBody] = useState<string>('{"user":"alice","role":"viewer"}');
  const [testStatus, setTestStatus] = useState<number>(200);
  const [testBody, setTestBody] = useState<string>('{"user":"bob","role":"admin"}');
  const [diffResult, setDiffResult] = useState<Record<string, unknown> | null>(null);

  const effectiveTarget = selectedEngagement?.target || targetDomain || "";

  const loadSurfaceTelemetry = useCallback(async () => {
    const q = effectiveTarget ? `?target=${encodeURIComponent(effectiveTarget)}` : "";
    const [swRes, cgRes] = await Promise.all([
      apiJson<SwarmTelemetryPayload>(`/api/control/swarm-telemetry${q}`),
      apiJson<AttackGraphSnapshot>("/api/attack_graph/snapshot"),
    ]);
    if (swRes.ok && swRes.data) {
      setTelemetry(swRes.data);
      if (swRes.data.two_brain_diffs?.length) {
        setSelectedDiff(swRes.data.two_brain_diffs[0]);
      }
    }
    if (cgRes.ok && cgRes.data) {
      setCausalGraph({
        ...cgRes.data,
        nodes: coerceGraphArray<AttackGraphNode>(cgRes.data.nodes),
        edges: coerceGraphArray<AttackGraphEdge>(cgRes.data.edges),
      });
    }
  }, [apiJson, effectiveTarget]);

  useEffect(() => {
    void loadSurfaceTelemetry();
  }, [loadSurfaceTelemetry]);

  const simulateWiretapStep = async () => {
    await apiJson("/api/control/swarm-telemetry/simulate-step", {
      method: "POST",
      body: {
        step_type: "EVIDENCE_DISCOVERED",
        node_name: effectiveTarget || "api.target/v2",
        agent: "BugHunter",
      },
    });
    await loadSurfaceTelemetry();
  };

  const runDiffAnalyzer = async (e: React.FormEvent) => {
    e.preventDefault();
    const res = await apiJson<{ differential?: Record<string, unknown> }>("/api/analyzer/diff", {
      method: "POST",
      body: {
        baseline_status: baseStatus,
        baseline_body: baseBody,
        test_status: testStatus,
        test_body: testBody,
      },
    });
    if (res.ok && res.data) {
      setDiffResult(res.data.differential || res.data);
    }
  };

  const roster = Array.isArray(telemetry?.swarm_roster) ? telemetry.swarm_roster : [];
  const wiretap = Array.isArray(telemetry?.wiretap_events) ? telemetry.wiretap_events : [];
  const diffs = Array.isArray(telemetry?.two_brain_diffs) ? telemetry.two_brain_diffs : [];
  const causalNodes = coerceGraphArray<AttackGraphNode>(causalGraph?.nodes);
  const causalEdges = coerceGraphArray<AttackGraphEdge>(causalGraph?.edges);

  return (
    <div className="space-y-5">
      {/* Primary Dual Graph + Paginated Table + Asset Inspector */}
      <AssetDualGraph />

      {/* Attack Path Snapshot & Swarm Roster */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-5">
        <section className="lg:col-span-7 sentinel-surface p-4 space-y-3">
          <div className="flex flex-wrap items-center justify-between gap-2 pb-2 border-b border-border-subtle">
            <div className="flex items-center gap-2">
              <Network className="w-4 h-4 text-sentinel-primary" />
              <h2 className="text-sm font-semibold text-ink-primary">{t("assets.attackGraphTitle")}</h2>
              <span
                title={`${causalEdges.length} edges`}
                className="text-xs font-mono px-2 py-0.5 rounded bg-elevated border border-border-subtle text-ink-secondary"
              >
                {causalNodes.length} {t("assets.nodesCount")}
              </span>
            </div>
            <div className="flex items-center gap-2">
              <button
                type="button"
                onClick={() => void loadSurfaceTelemetry()}
                className="h-8 px-2.5 rounded border border-border-subtle bg-elevated hover:border-border-strong text-xs text-ink-primary flex items-center gap-1"
              >
                <RefreshCw className="w-3.5 h-3.5" />
                <span>{t("common.refresh")}</span>
              </button>
            </div>
          </div>

          {causalNodes.length === 0 ? (
            <div className="py-6 text-center text-xs text-ink-muted">
              {t("assets.emptyAssets")}
            </div>
          ) : (
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 max-h-64 overflow-y-auto">
              {causalNodes.map((n, idx) => (
                <div key={`${n.id || n.node_id || "node"}-${idx}`} className="p-2.5 rounded bg-elevated border border-border-subtle text-xs space-y-1">
                  <div className="flex items-center justify-between gap-2">
                    <span className="font-mono text-sentinel-primary">{n.node_type || "NODE"}</span>
                    {typeof n.risk_score === "number" && (
                      <span className="font-mono text-sentinel-warning tabular-nums">
                        Risk {n.risk_score}
                      </span>
                    )}
                  </div>
                  <div className="font-mono text-ink-primary ltr-isolate truncate">{n.label || n.name || n.id || n.node_id}</div>
                </div>
              ))}
            </div>
          )}
        </section>

        <section className="lg:col-span-5 sentinel-surface p-4 space-y-3">
          <div className="flex items-center justify-between pb-2 border-b border-border-subtle">
            <div className="flex items-center gap-2">
              <Users className="w-4 h-4 text-sentinel-ai" />
              <h2 className="text-sm font-semibold text-ink-primary">Swarm Roster</h2>
            </div>
            <span
              className={`text-xs font-mono px-2 py-0.5 rounded border ${
                telemetry?.swarm_status === "ONLINE"
                  ? "bg-[var(--accent-success-bg)] text-sentinel-success border-[var(--accent-success)]/35"
                  : "bg-elevated text-ink-muted border-border-subtle"
              }`}
            >
              {telemetry?.swarm_status || t("status.standby")}
            </span>
          </div>

          {roster.length === 0 ? (
            <div className="py-6 text-center text-xs text-ink-muted">
              No active runs in swarm roster (STANDBY).
            </div>
          ) : (
            <div className="space-y-2 max-h-64 overflow-y-auto">
              {roster.map((item, idx) => (
                <div key={`${item.role || "role"}-${idx}`} className="p-2.5 rounded bg-elevated border border-border-subtle text-xs space-y-1">
                  <div className="flex items-center justify-between">
                    <span className="font-mono font-semibold text-ink-primary ltr-isolate">{item.agent}</span>
                    <span className="text-[11px] font-mono px-1.5 py-0.5 rounded bg-[var(--accent-primary-bg)] text-sentinel-primary">
                      {item.status}
                    </span>
                  </div>
                  <div className="text-[11px] font-mono text-ink-muted ltr-isolate">
                    {item.role} · {item.node}
                  </div>
                </div>
              ))}
            </div>
          )}
        </section>
      </div>

      {/* Inter-Agent Wiretap + Two-Brain Differential Proof */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-5">
        <section className="lg:col-span-6 sentinel-surface p-4 space-y-3">
          <div className="flex flex-wrap items-center justify-between gap-2 pb-2 border-b border-border-subtle">
            <div className="flex items-center gap-2">
              <Radio className="w-4 h-4 text-sentinel-primary" />
              <h2 className="text-sm font-semibold text-ink-primary">{t("logs.wiretapTitle")}</h2>
            </div>
            <button
              type="button"
              onClick={() => void simulateWiretapStep()}
              className="h-8 px-2.5 rounded border border-border-subtle bg-elevated hover:border-border-strong text-xs text-ink-secondary hover:text-ink-primary flex items-center gap-1"
            >
              <Sparkles className="w-3.5 h-3.5 text-sentinel-ai" />
              <span>Emit Test Step</span>
            </button>
          </div>

          <div className="space-y-2 max-h-72 overflow-y-auto pe-1">
            {wiretap.length === 0 ? (
              <div className="py-6 text-center text-xs text-ink-muted">{t("common.noData")}</div>
            ) : (
              wiretap.map((ev, idx) => (
                <div key={`${ev.id || "ev"}-${idx}`} className="p-2.5 rounded bg-inset border border-border-subtle text-xs space-y-1">
                  <div className="flex items-center justify-between gap-2 font-mono text-[11px]">
                    <span className="text-sentinel-primary ltr-isolate">
                      {ev.from_agent} → {ev.to_agent}
                    </span>
                    <div className="flex items-center gap-1.5">
                      {ev.simulated && (
                        <span className="px-1.5 py-0.5 rounded bg-[var(--accent-warning-bg)] text-sentinel-warning border border-[var(--accent-warning)]/35">
                          SIMULATED
                        </span>
                      )}
                      <span className="text-ink-muted tabular-nums">{ev.time}</span>
                    </div>
                  </div>
                  <div className="font-mono text-ink-secondary break-all">{ev.summary || ev.type}</div>
                </div>
              ))
            )}
          </div>
        </section>

        <section className="lg:col-span-6 sentinel-surface p-4 space-y-3">
          <div className="flex items-center justify-between pb-2 border-b border-border-subtle">
            <div className="flex items-center gap-2">
              <GitCompare className="w-4 h-4 text-sentinel-success" />
              <h2 className="text-sm font-semibold text-ink-primary">{t("findings.twoBrainTitle")}</h2>
            </div>
            <span className="text-xs font-mono text-ink-muted">{diffs.length} verdicts</span>
          </div>

          {selectedDiff && (
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-2.5 text-xs">
              <div className="p-3 rounded bg-inset border border-border-subtle space-y-1">
                <div className="font-semibold text-sentinel-primary">{t("findings.brainATitle")}</div>
                <div className="font-mono text-ink-primary break-words">{selectedDiff.brain_a_hypothesis || selectedDiff.title}</div>
              </div>
              <div className="p-3 rounded bg-inset border border-border-subtle space-y-1">
                <div className="font-semibold text-sentinel-success">{t("findings.brainBTitle")}</div>
                <div className="font-mono text-ink-secondary break-words">{selectedDiff.brain_b_verification || "—"}</div>
              </div>
            </div>
          )}

          {/* Interactive Response Differential Analyzer */}
          <form onSubmit={runDiffAnalyzer} className="space-y-2 pt-2 border-t border-border-subtle text-xs">
            <div className="font-semibold text-ink-secondary flex items-center gap-1.5">
              <Activity className="w-3.5 h-3.5 text-sentinel-primary" />
              <span>Differential Response Comparator (/api/analyzer/diff)</span>
            </div>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
              <div className="space-y-1">
                <div className="flex items-center justify-between text-ink-muted">
                  <span>Baseline Status</span>
                  <input
                    type="number"
                    value={baseStatus}
                    onChange={(e) => setBaseStatus(Number(e.target.value) || 200)}
                    className="w-20 h-6 px-2 rounded bg-inset border border-border-subtle font-mono ltr-isolate"
                  />
                </div>
                <textarea
                  rows={2}
                  dir="ltr"
                  value={baseBody}
                  onChange={(e) => setBaseBody(e.target.value)}
                  className="ltr-isolate w-full p-2 rounded bg-inset border border-border-subtle font-mono text-[11px]"
                />
              </div>
              <div className="space-y-1">
                <div className="flex items-center justify-between text-ink-muted">
                  <span>Mutated Status</span>
                  <input
                    type="number"
                    value={testStatus}
                    onChange={(e) => setTestStatus(Number(e.target.value) || 200)}
                    className="w-20 h-6 px-2 rounded bg-inset border border-border-subtle font-mono ltr-isolate"
                  />
                </div>
                <textarea
                  rows={2}
                  dir="ltr"
                  value={testBody}
                  onChange={(e) => setTestBody(e.target.value)}
                  className="ltr-isolate w-full p-2 rounded bg-inset border border-border-subtle font-mono text-[11px]"
                />
              </div>
            </div>
            <button
              type="submit"
              className="h-8 px-3 rounded bg-elevated border border-border-strong hover:border-sentinel-primary text-ink-primary font-medium"
            >
              Compute Causal Diff
            </button>
            {diffResult && (
              <pre dir="ltr" className="ltr-isolate p-2.5 rounded bg-inset border border-border-subtle font-mono text-[11px] text-ink-secondary overflow-x-auto max-h-36">
                {JSON.stringify(diffResult, null, 2)}
              </pre>
            )}
          </form>
        </section>
      </div>
    </div>
  );
}
