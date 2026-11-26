"use client";

import React, { useCallback, useEffect, useMemo, useState } from "react";
import {
  Bot,
  Sparkles,
  Wrench,
  Cpu,
  Server,
  Box,
  Play,
  Loader2,
  Send,
  Wand2,
} from "lucide-react";
import { usePlatform } from "@/lib/platform-context";
import { useI18n } from "@/lib/i18n";
import { renderSafeMarkdown } from "@/lib/sanitize";

interface AgentItem {
  id: string;
  name: string;
  description: string;
  tools: string[];
  status: string;
}

interface SkillCatalogItem {
  name: string;
  category?: string;
  layer?: string;
  description?: string;
}

interface KaliToolItem {
  name: string;
  installed: boolean;
  status: string;
  path: string;
}

interface CliEngineItem {
  engine: string;
  display_name: string;
  capabilities?: string[];
  supports_streaming?: boolean;
}

const ELITE_PROBERS = [
  "http_smuggling",
  "cache_poisoning",
  "oauth2_abuse",
  "prototype_pollution",
  "path_traversal",
  "jwt_advanced",
];

export default function ArsenalPage() {
  const { selectedEngagement, apiJson } = usePlatform();
  const { t } = useI18n();

  const [agents, setAgents] = useState<AgentItem[]>([]);
  const [selectedAgentId, setSelectedAgentId] = useState<string>("");
  const [agentPrompt, setAgentPrompt] = useState<string>("");
  const [agentReplyMd, setAgentReplyMd] = useState<string>("");
  const [agentSending, setAgentSending] = useState<boolean>(false);

  const [skills, setSkills] = useState<SkillCatalogItem[]>([]);
  const [skillFilter, setSkillFilter] = useState<string>("");
  const [eliteSkill, setEliteSkill] = useState<string>(ELITE_PROBERS[0]);
  const [eliteTarget, setEliteTarget] = useState<string>("");
  const [eliteResult, setEliteResult] = useState<Record<string, unknown> | null>(null);

  const [tools, setTools] = useState<KaliToolItem[]>([]);
  const [toolFilter, setToolFilter] = useState<string>("");
  const [toolTestOut, setToolTestOut] = useState<string>("");
  const [synthTool, setSynthTool] = useState<string>("nuclei");
  const [synthTarget, setSynthTarget] = useState<string>("");
  const [synthWaf, setSynthWaf] = useState<string>("");
  const [synthResult, setSynthResult] = useState<Record<string, unknown> | null>(null);

  const [engines, setEngines] = useState<CliEngineItem[]>([]);
  const [selfcheckOut, setSelfcheckOut] = useState<Record<string, unknown> | null>(null);
  const [mcpStatus, setMcpStatus] = useState<Record<string, unknown> | null>(null);
  const [mcpServers, setMcpServers] = useState<Array<Record<string, unknown>>>([]);
  const [mcpServerId, setMcpServerId] = useState<string>("hunter-arsenal");
  const [mcpToolName, setMcpToolName] = useState<string>("");
  const [mcpArgsJson, setMcpArgsJson] = useState<string>("{}");
  const [mcpCallOut, setMcpCallOut] = useState<Record<string, unknown> | null>(null);
  const [sandboxStatus, setSandboxStatus] = useState<Record<string, unknown> | null>(null);
  const [sandboxCmd, setSandboxCmd] = useState<string>("python --version");
  const [sandboxOut, setSandboxOut] = useState<Record<string, unknown> | null>(null);

  const loadArsenal = useCallback(async () => {
    const [agR, skR, tlR, engR, mcpR, mcpListR, sbR] = await Promise.all([
      apiJson<{ agents?: AgentItem[] }>("/api/control/agents"),
      apiJson<{ skills?: SkillCatalogItem[] }>("/api/skills/catalog"),
      apiJson<{ tools?: KaliToolItem[] }>("/api/control/tools"),
      apiJson<{ engines?: CliEngineItem[] }>("/api/engines"),
      apiJson<Record<string, unknown>>("/api/opencode/mcp-status"),
      apiJson<{ servers?: Array<Record<string, unknown>> }>("/api/mcp/servers"),
      apiJson<Record<string, unknown>>("/api/sandbox/health"),
    ]);
    if (agR.ok && Array.isArray(agR.data?.agents)) {
      setAgents(agR.data.agents);
      if (!selectedAgentId && agR.data.agents[0]) setSelectedAgentId(agR.data.agents[0].id);
    }
    if (skR.ok && Array.isArray(skR.data?.skills)) setSkills(skR.data.skills);
    if (tlR.ok && Array.isArray(tlR.data?.tools)) setTools(tlR.data.tools);
    if (engR.ok && Array.isArray(engR.data?.engines)) setEngines(engR.data.engines);
    if (mcpR.ok && mcpR.data) setMcpStatus(mcpR.data);
    if (mcpListR.ok && Array.isArray(mcpListR.data?.servers)) setMcpServers(mcpListR.data.servers);
    if (sbR.ok && sbR.data) setSandboxStatus(sbR.data);
  }, [apiJson, selectedAgentId]);

  useEffect(() => {
    void loadArsenal();
  }, [loadArsenal]);

  const sendAgentInstruction = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedAgentId || !agentPrompt.trim()) return;
    setAgentSending(true);
    const res = await apiJson<{ response?: string; message?: string }>("/api/control/agent/chat", {
      method: "POST",
      body: {
        agent_id: selectedAgentId,
        message: agentPrompt.trim(),
        target: selectedEngagement?.target || undefined,
      },
    });
    setAgentSending(false);
    setAgentReplyMd(res.ok ? res.data?.response || "" : res.error || res.data?.message || "Error");
  };

  const runEliteProber = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!eliteTarget.trim()) return;
    const res = await apiJson<Record<string, unknown>>("/api/enhanced/skills/elite-run", {
      method: "POST",
      body: { skill_name: eliteSkill, target_url: eliteTarget.trim() },
    });
    setEliteResult(res.data || { error: res.error });
  };

  const testTool = async (toolName: string) => {
    const res = await apiJson<{ output?: string; message?: string }>("/api/control/tools/test", {
      method: "POST",
      body: { tool_name: toolName },
    });
    setToolTestOut(res.ok ? res.data?.output || "PASS" : res.error || res.data?.message || "Failed");
  };

  const synthesizeCommand = async (e: React.FormEvent) => {
    e.preventDefault();
    const tgt = synthTarget.trim() || selectedEngagement?.target || "https://example.com";
    const res = await apiJson<Record<string, unknown>>("/api/enhanced/arsenal/synthesize", {
      method: "POST",
      body: { tool_name: synthTool.trim(), target: tgt, waf_name: synthWaf.trim() || null },
    });
    setSynthResult(res.data || { error: res.error });
  };

  const runEngineSelfcheck = async () => {
    const res = await apiJson<Record<string, unknown>>("/api/engines/selfcheck", {
      method: "POST",
      body: {},
    });
    if (res.data) setSelfcheckOut(res.data);
  };

  const runSandbox = async (e: React.FormEvent) => {
    e.preventDefault();
    const parts = sandboxCmd.trim().split(/\s+/).filter(Boolean);
    if (!parts.length) return;
    const res = await apiJson<Record<string, unknown>>("/api/sandbox/run", {
      method: "POST",
      body: { command: parts },
    });
    if (res.data) setSandboxOut(res.data);
  };

  const invokeMcpTool = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!mcpServerId.trim() || !mcpToolName.trim()) return;
    let parsedArgs: Record<string, unknown> = {};
    try {
      parsedArgs = JSON.parse(mcpArgsJson || "{}") as Record<string, unknown>;
    } catch {
      setMcpCallOut({ ok: false, error: "Invalid JSON arguments" });
      return;
    }
    const res = await apiJson<Record<string, unknown>>("/api/mcp/call", {
      method: "POST",
      body: {
        server_id: mcpServerId.trim(),
        tool_name: mcpToolName.trim(),
        arguments: parsedArgs,
      },
    });
    setMcpCallOut(res.data || { ok: false, error: res.error });
  };

  const filteredSkills = useMemo(() => {
    const q = skillFilter.trim().toLowerCase();
    return skills.filter(
      (s) => !q || s.name.toLowerCase().includes(q) || (s.category || "").toLowerCase().includes(q)
    );
  }, [skills, skillFilter]);

  const filteredTools = useMemo(() => {
    const q = toolFilter.trim().toLowerCase();
    return tools.filter((tl) => !q || tl.name.toLowerCase().includes(q));
  }, [tools, toolFilter]);

  const replyHtml = useMemo(() => (agentReplyMd ? renderSafeMarkdown(agentReplyMd) : ""), [agentReplyMd]);

  return (
    <div className="space-y-5">
      {/* Specialist Agents + Direct Chat */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-5">
        <section className="lg:col-span-5 sentinel-surface p-4 space-y-3">
          <div className="flex items-center justify-between pb-2 border-b border-border-subtle">
            <div className="flex items-center gap-2">
              <Bot className="w-4 h-4 text-sentinel-ai" />
              <h1 className="text-sm font-semibold text-ink-primary">{t("sections.agents")}</h1>
            </div>
            <span className="text-xs font-mono text-ink-muted">{agents.length}</span>
          </div>

          <div className="space-y-1.5 max-h-72 overflow-y-auto pe-1">
            {agents.map((ag) => (
              <button
                key={ag.id}
                type="button"
                onClick={() => setSelectedAgentId(ag.id)}
                className={`w-full p-2.5 rounded border text-start text-xs space-y-1 transition-colors ${
                  selectedAgentId === ag.id
                    ? "bg-[var(--accent-ai-bg)] border-sentinel-ai text-ink-primary"
                    : "bg-elevated border-border-subtle hover:border-border-strong text-ink-secondary"
                }`}
              >
                <div className="font-mono font-semibold text-ink-primary">{ag.name}</div>
                <div className="text-[11px] text-ink-muted line-clamp-2">{ag.description}</div>
              </button>
            ))}
          </div>
        </section>

        <section className="lg:col-span-7 sentinel-surface p-4 flex flex-col gap-3">
          <div className="flex items-center justify-between pb-2 border-b border-border-subtle">
            <span className="text-sm font-semibold text-ink-primary">
              Direct Specialist Chat ({selectedAgentId || "none"})
            </span>
          </div>

          <form onSubmit={sendAgentInstruction} className="flex gap-2 text-xs">
            <input
              type="text"
              value={agentPrompt}
              onChange={(e) => setAgentPrompt(e.target.value)}
              placeholder="Send targeted security task to specialist agent..."
              className="flex-1 h-9 px-3 rounded bg-inset border border-border-subtle"
            />
            <button
              type="submit"
              disabled={agentSending || !selectedAgentId}
              className="h-9 px-3.5 rounded bg-sentinel-primary text-sentinel-onAccent font-semibold flex items-center gap-1.5 disabled:opacity-50"
            >
              {agentSending ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Send className="w-3.5 h-3.5" />}
              <span>{t("common.submit")}</span>
            </button>
          </form>

          {replyHtml ? (
            <div
              className="sentinel-prose flex-1 max-h-60 overflow-y-auto p-3 rounded bg-inset border border-border-subtle"
              dangerouslySetInnerHTML={{ __html: replyHtml }}
            />
          ) : (
            <div className="flex-1 flex items-center justify-center text-xs text-ink-muted py-10">
              Select a specialist agent and issue an instruction.
            </div>
          )}
        </section>
      </div>

      {/* Skills Matrix + 6 Elite Exploit Probers */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-5">
        <section className="lg:col-span-7 sentinel-surface p-4 space-y-3">
          <div className="flex flex-wrap items-center justify-between gap-2 pb-2 border-b border-border-subtle">
            <div className="flex items-center gap-2">
              <Sparkles className="w-4 h-4 text-sentinel-primary" />
              <h2 className="text-sm font-semibold text-ink-primary">
                {t("sections.skills")} ({skills.length})
              </h2>
            </div>
            <input
              type="search"
              value={skillFilter}
              onChange={(e) => setSkillFilter(e.target.value)}
              placeholder={t("common.search")}
              className="h-8 px-2.5 rounded bg-inset border border-border-subtle text-xs"
            />
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 max-h-64 overflow-y-auto pe-1">
            {filteredSkills.slice(0, 80).map((sk) => (
              <div key={sk.name} className="p-2.5 rounded bg-elevated border border-border-subtle text-xs space-y-1">
                <div className="flex items-center justify-between gap-1">
                  <span className="font-mono font-semibold text-sentinel-primary truncate">{sk.name}</span>
                  <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-inset text-ink-muted shrink-0">
                    {sk.layer || sk.category || "skill"}
                  </span>
                </div>
                <div className="text-[11px] text-ink-muted line-clamp-2">{sk.description}</div>
              </div>
            ))}
          </div>
        </section>

        <section className="lg:col-span-5 sentinel-surface p-4 space-y-3">
          <div className="flex items-center gap-2 pb-2 border-b border-border-subtle">
            <Play className="w-4 h-4 text-sentinel-danger" />
            <h2 className="text-sm font-semibold text-ink-primary">6 Elite Exploit Probers</h2>
          </div>

          <form onSubmit={runEliteProber} className="space-y-2 text-xs">
            <select
              value={eliteSkill}
              onChange={(e) => setEliteSkill(e.target.value)}
              className="w-full h-9 px-2.5 rounded bg-inset border border-border-subtle font-mono"
            >
              {ELITE_PROBERS.map((p) => (
                <option key={p} value={p}>{p}</option>
              ))}
            </select>
            <div className="flex gap-2">
              <input
                type="text"
                dir="ltr"
                value={eliteTarget}
                onChange={(e) => setEliteTarget(e.target.value)}
                placeholder="https://example.com/endpoint"
                className="ltr-isolate flex-1 h-9 px-3 rounded bg-inset border border-border-subtle font-mono"
              />
              <button
                type="submit"
                className="h-9 px-3 rounded bg-sentinel-primary text-sentinel-onAccent font-semibold"
              >
                {t("common.run")}
              </button>
            </div>
          </form>

          {eliteResult && (
            <pre dir="ltr" className="ltr-isolate p-2.5 rounded bg-inset border border-border-subtle font-mono text-[11px] max-h-40 overflow-auto">
              {JSON.stringify(eliteResult, null, 2)}
            </pre>
          )}
        </section>
      </div>

      {/* Kali Tools Catalog + AI Command Synthesizer */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-5">
        <section className="lg:col-span-7 sentinel-surface p-4 space-y-3">
          <div className="flex flex-wrap items-center justify-between gap-2 pb-2 border-b border-border-subtle">
            <div className="flex items-center gap-2">
              <Wrench className="w-4 h-4 text-sentinel-warning" />
              <h2 className="text-sm font-semibold text-ink-primary">{t("tools.title")}</h2>
            </div>
            <input
              type="search"
              value={toolFilter}
              onChange={(e) => setToolFilter(e.target.value)}
              placeholder={t("tools.searchToolsPlaceholder")}
              className="h-8 px-2.5 rounded bg-inset border border-border-subtle text-xs"
            />
          </div>

          <div className="overflow-x-auto max-h-60 overflow-y-auto border border-border-subtle rounded bg-inset">
            <table className="w-full text-xs border-collapse">
              <thead className="bg-elevated border-b border-border-subtle text-ink-muted sticky top-0">
                <tr>
                  <th className="py-2 px-3 text-start">{t("tools.colTool")}</th>
                  <th className="py-2 px-3 text-start">{t("tools.colStatus")}</th>
                  <th className="py-2 px-3 text-start">{t("tools.colHealth")}</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border-subtle font-mono">
                {filteredTools.map((tl) => (
                  <tr key={tl.name} className="ltr-isolate">
                    <td className="py-1.5 px-3 text-ink-primary">{tl.name}</td>
                    <td className="py-1.5 px-3">
                      <span className={tl.installed ? "text-sentinel-success" : "text-ink-muted"}>
                        {tl.installed ? "INSTALLED" : "MISSING"}
                      </span>
                    </td>
                    <td className="py-1.5 px-3">
                      <button
                        type="button"
                        disabled={!tl.installed}
                        onClick={() => void testTool(tl.name)}
                        className="px-2 py-0.5 rounded bg-elevated border border-border-subtle disabled:opacity-40"
                      >
                        {t("tools.checkHealth")}
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          {toolTestOut && (
            <pre dir="ltr" className="ltr-isolate p-2.5 rounded bg-inset border border-border-subtle font-mono text-[11px] max-h-24 overflow-auto">
              {toolTestOut}
            </pre>
          )}
        </section>

        <section className="lg:col-span-5 sentinel-surface p-4 space-y-3">
          <div className="flex items-center gap-2 pb-2 border-b border-border-subtle">
            <Wand2 className="w-4 h-4 text-sentinel-primary" />
            <h2 className="text-sm font-semibold text-ink-primary">{t("tools.synthesizeCmd")}</h2>
          </div>
          <form onSubmit={synthesizeCommand} className="space-y-2 text-xs">
            <div className="grid grid-cols-2 gap-2">
              <input
                type="text"
                dir="ltr"
                value={synthTool}
                onChange={(e) => setSynthTool(e.target.value)}
                placeholder="nuclei"
                className="ltr-isolate h-8 px-2.5 rounded bg-inset border border-border-subtle font-mono"
              />
              <input
                type="text"
                dir="ltr"
                value={synthWaf}
                onChange={(e) => setSynthWaf(e.target.value)}
                placeholder="WAF (e.g. Cloudflare)"
                className="ltr-isolate h-8 px-2.5 rounded bg-inset border border-border-subtle font-mono"
              />
            </div>
            <div className="flex gap-2">
              <input
                type="text"
                dir="ltr"
                value={synthTarget}
                onChange={(e) => setSynthTarget(e.target.value)}
                placeholder="https://example.com"
                className="ltr-isolate flex-1 h-8 px-2.5 rounded bg-inset border border-border-subtle font-mono"
              />
              <button type="submit" className="h-8 px-3 rounded bg-sentinel-primary text-sentinel-onAccent font-semibold">
                Synthesize
              </button>
            </div>
          </form>

          {synthResult && (
            <pre dir="ltr" className="ltr-isolate p-2.5 rounded bg-inset border border-border-subtle font-mono text-[11px] max-h-40 overflow-auto">
              {JSON.stringify(synthResult, null, 2)}
            </pre>
          )}
        </section>
      </div>

      {/* CLI Engines, MCP Servers & Sandbox */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-5">
        <section className="sentinel-surface p-4 space-y-3">
          <div className="flex items-center justify-between pb-2 border-b border-border-subtle">
            <div className="flex items-center gap-2">
              <Cpu className="w-4 h-4 text-sentinel-primary" />
              <h2 className="text-sm font-semibold text-ink-primary">CLI Engines</h2>
            </div>
            <button
              type="button"
              onClick={() => void runEngineSelfcheck()}
              className="h-7 px-2 rounded border border-border-subtle bg-elevated text-xs font-mono"
            >
              Selfcheck
            </button>
          </div>
          <div className="space-y-1.5 text-xs">
            {engines.map((e) => (
              <div key={e.engine} className="p-2 rounded bg-elevated border border-border-subtle font-mono flex justify-between">
                <span>{e.display_name || e.engine}</span>
                <span className="text-ink-muted">{e.supports_streaming ? "STREAM" : "SYNC"}</span>
              </div>
            ))}
          </div>
          {selfcheckOut && (
            <pre dir="ltr" className="ltr-isolate p-2 rounded bg-inset border border-border-subtle font-mono text-[10px] max-h-32 overflow-auto">
              {JSON.stringify(selfcheckOut, null, 2)}
            </pre>
          )}
        </section>

        <section className="sentinel-surface p-4 space-y-3">
          <div className="flex items-center gap-2 pb-2 border-b border-border-subtle">
            <Server className="w-4 h-4 text-sentinel-success" />
            <h2 className="text-sm font-semibold text-ink-primary">{t("mcp.title")}</h2>
          </div>
          <form onSubmit={invokeMcpTool} className="space-y-2 text-xs">
            <div className="grid grid-cols-2 gap-2">
              <input
                type="text"
                dir="ltr"
                value={mcpServerId}
                onChange={(e) => setMcpServerId(e.target.value)}
                placeholder="server_id"
                className="ltr-isolate h-8 px-2.5 rounded bg-inset border border-border-subtle font-mono"
              />
              <input
                type="text"
                dir="ltr"
                value={mcpToolName}
                onChange={(e) => setMcpToolName(e.target.value)}
                placeholder="tool_name"
                className="ltr-isolate h-8 px-2.5 rounded bg-inset border border-border-subtle font-mono"
              />
            </div>
            <div className="flex gap-2">
              <input
                type="text"
                dir="ltr"
                value={mcpArgsJson}
                onChange={(e) => setMcpArgsJson(e.target.value)}
                placeholder="{}"
                className="ltr-isolate flex-1 h-8 px-2.5 rounded bg-inset border border-border-subtle font-mono"
              />
              <button type="submit" className="h-8 px-3 rounded bg-elevated border border-border-strong font-semibold">
                {t("mcp.callTool")}
              </button>
            </div>
          </form>
          <pre dir="ltr" className="ltr-isolate p-2.5 rounded bg-inset border border-border-subtle font-mono text-[11px] max-h-36 overflow-auto">
            {JSON.stringify(mcpCallOut || { opencode_mcp: mcpStatus, registered_servers: mcpServers }, null, 2)}
          </pre>
        </section>

        <section className="sentinel-surface p-4 space-y-3">
          <div className="flex items-center justify-between pb-2 border-b border-border-subtle">
            <div className="flex items-center gap-2">
              <Box className="w-4 h-4 text-sentinel-ai" />
              <h2 className="text-sm font-semibold text-ink-primary">Local Sandbox</h2>
            </div>
            <span className="font-mono text-xs text-sentinel-success">
              {sandboxStatus?.ok ? "READY" : "CHECK"}
            </span>
          </div>
          <form onSubmit={runSandbox} className="flex gap-2 text-xs">
            <input
              type="text"
              dir="ltr"
              value={sandboxCmd}
              onChange={(e) => setSandboxCmd(e.target.value)}
              className="ltr-isolate flex-1 h-8 px-2.5 rounded bg-inset border border-border-subtle font-mono"
            />
            <button type="submit" className="h-8 px-3 rounded bg-elevated border border-border-strong font-semibold">
              {t("common.run")}
            </button>
          </form>
          {sandboxOut && (
            <pre dir="ltr" className="ltr-isolate p-2 rounded bg-inset border border-border-subtle font-mono text-[11px] max-h-40 overflow-auto">
              {JSON.stringify(sandboxOut, null, 2)}
            </pre>
          )}
        </section>
      </div>
    </div>
  );
}
