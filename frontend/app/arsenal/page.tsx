"use client";

import React, { useCallback, useEffect, useMemo, useState } from "react";
import {
  Bot,
  Sparkles,
  Wrench,
  Cpu,
  Box,
  Play,
  Loader2,
  Send,
  Wand2,
  BookOpen,
  ChevronLeft,
  ChevronRight,
  X,
  CheckCircle2,
  AlertCircle,
} from "lucide-react";
import McpManagerModal from "@/components/McpManagerModal";
import { usePlatform } from "@/lib/platform-context";
import { useI18n } from "@/lib/i18n";
import { renderSafeMarkdown } from "@/lib/sanitize";
import { sanitizePlainTerminalText } from "@/lib/terminal-sanitizer";
import { useFocusTrap } from "@/hooks/use-focus-trap";

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

interface ToolTestOutcome {
  toolName: string;
  ok: boolean;
  status: "PASS" | "FAIL";
  returncode?: number | null;
  stdout?: string;
  stderr?: string;
  message?: string;
}

const ELITE_PROBERS = [
  "http_smuggling",
  "cache_poisoning",
  "oauth2_abuse",
  "prototype_pollution",
  "path_traversal",
  "jwt_advanced",
];

const SKILLS_PAGE_SIZE = 24;

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
  const [skillPage, setSkillPage] = useState<number>(1);
  const [eliteSkill, setEliteSkill] = useState<string>(ELITE_PROBERS[0]);
  const [eliteTarget, setEliteTarget] = useState<string>("");
  const [eliteResult, setEliteResult] = useState<Record<string, unknown> | null>(null);

  const [tools, setTools] = useState<KaliToolItem[]>([]);
  const [toolFilter, setToolFilter] = useState<string>("");
  const [toolTestResult, setToolTestResult] = useState<ToolTestOutcome | null>(null);
  const [testingToolName, setTestingToolName] = useState<string | null>(null);
  const [inspectedTool, setInspectedTool] = useState<{ name: string; detail: Record<string, unknown> } | null>(null);
  const toolModalTrapRef = useFocusTrap(Boolean(inspectedTool), () => setInspectedTool(null));

  const [synthTool, setSynthTool] = useState<string>("nuclei");
  const [synthTarget, setSynthTarget] = useState<string>("");
  const [synthWaf, setSynthWaf] = useState<string>("");
  const [synthResult, setSynthResult] = useState<Record<string, unknown> | null>(null);

  // Wordlist Explorer
  const [wordlistRoots, setWordlistRoots] = useState<string[]>([]);
  const [wordlistQuery, setWordlistQuery] = useState<string>("");
  const [wordlistMatches, setWordlistMatches] = useState<Array<Record<string, unknown>>>([]);

  const [engines, setEngines] = useState<CliEngineItem[]>([]);
  const [selfcheckOut, setSelfcheckOut] = useState<Record<string, unknown> | null>(null);
  const [sandboxStatus, setSandboxStatus] = useState<Record<string, unknown> | null>(null);
  const [sandboxCmd, setSandboxCmd] = useState<string>("python --version");
  const [sandboxOut, setSandboxOut] = useState<Record<string, unknown> | null>(null);

  const loadArsenal = useCallback(async () => {
    const [agR, skR, tlR, engR, sbR, wlR] = await Promise.all([
      apiJson<{ agents?: AgentItem[] }>("/api/control/agents"),
      apiJson<{ skills?: SkillCatalogItem[] }>("/api/skills/catalog"),
      apiJson<{ tools?: KaliToolItem[] }>("/api/control/tools"),
      apiJson<{ engines?: CliEngineItem[] }>("/api/engines"),
      apiJson<Record<string, unknown>>("/api/sandbox/health"),
      apiJson<{ roots?: string[]; available?: string[] }>("/api/wordlists/roots"),
    ]);
    if (agR.ok && Array.isArray(agR.data?.agents)) {
      const normalizedAgents = agR.data.agents
        .filter((ag): ag is AgentItem => Boolean(ag && typeof ag === "object"))
        .map((ag) => ({
          id: String(ag.id || ag.name || ""),
          name: String(ag.name || ag.id || "agent"),
          description: String(ag.description || ""),
          tools: Array.isArray(ag.tools) ? ag.tools.map(String) : [],
          status: String(ag.status || "ready"),
        }));
      setAgents(normalizedAgents);
      if (!selectedAgentId && normalizedAgents[0]?.id) setSelectedAgentId(normalizedAgents[0].id);
    }
    if (skR.ok && Array.isArray(skR.data?.skills)) {
      const normalizedSkills = skR.data.skills
        .map((sk: unknown): SkillCatalogItem | null => {
          if (typeof sk === "string") return { name: sk };
          if (sk && typeof sk === "object") {
            const obj = sk as Record<string, unknown>;
            const name = String(obj.name || "");
            if (!name) return null;
            return {
              name,
              category: typeof obj.category === "string" ? obj.category : undefined,
              layer: typeof obj.layer === "string" ? obj.layer : undefined,
              description: typeof obj.description === "string" ? obj.description : undefined,
            };
          }
          return null;
        })
        .filter((sk): sk is SkillCatalogItem => sk !== null);
      setSkills(normalizedSkills);
    }
    if (tlR.ok && Array.isArray(tlR.data?.tools)) {
      const normalizedTools = tlR.data.tools
        .map((tl: unknown): KaliToolItem | null => {
          if (typeof tl === "string") {
            return { name: tl, installed: true, status: "installed", path: "" };
          }
          if (tl && typeof tl === "object") {
            const obj = tl as Record<string, unknown>;
            const name = String(obj.name || obj.tool || "");
            if (!name) return null;
            const installed = Boolean(obj.installed ?? true);
            return {
              name,
              installed,
              status: String(obj.status || (installed ? "installed" : "missing")),
              path: String(obj.path || ""),
            };
          }
          return null;
        })
        .filter((tl): tl is KaliToolItem => tl !== null);
      setTools(normalizedTools);
    }
    if (engR.ok && Array.isArray(engR.data?.engines)) setEngines(engR.data.engines);
    if (sbR.ok && sbR.data) setSandboxStatus(sbR.data);
    if (wlR.ok && wlR.data) {
      const roots = Array.isArray(wlR.data.roots)
        ? wlR.data.roots
        : Array.isArray(wlR.data.available)
          ? wlR.data.available
          : [];
      setWordlistRoots(roots.map(String));
    }
  }, [apiJson, selectedAgentId]);

  useEffect(() => {
    void loadArsenal();
  }, [loadArsenal]);

  const sendAgentInstruction = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedAgentId || !agentPrompt.trim()) return;
    setAgentSending(true);
    const res = await apiJson<{ response?: string; reply?: string; message?: string }>("/api/control/agent/chat", {
      method: "POST",
      body: {
        agent_id: selectedAgentId,
        message: agentPrompt.trim(),
        target: selectedEngagement?.target || undefined,
      },
    });
    setAgentSending(false);
    setAgentReplyMd(res.ok ? res.data?.response || res.data?.reply || "" : res.error || res.data?.message || t("common.error"));
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

  // Truthful PASS/FAIL with stdout, stderr & returncode — never masks failures as PASS
  const testTool = async (toolName: string) => {
    setTestingToolName(toolName);
    const res = await apiJson<{
      ok?: boolean;
      status?: string;
      returncode?: number | null;
      stdout?: string;
      stderr?: string;
      output?: string;
      message?: string;
      error?: string;
    }>("/api/control/tools/test", {
      method: "POST",
      body: { tool_name: toolName },
    });
    setTestingToolName(null);
    const passed = Boolean(
      res.ok &&
        res.data?.ok !== false &&
        (res.data?.status ? res.data.status.toUpperCase() === "PASS" : true)
    );
    setToolTestResult({
      toolName,
      ok: passed,
      status: passed ? "PASS" : "FAIL",
      returncode: typeof res.data?.returncode === "number" ? res.data.returncode : null,
      stdout: res.data?.stdout || res.data?.output || "",
      stderr: res.data?.stderr || res.data?.error || (!passed ? res.error : "") || "",
      message: res.data?.message || "",
    });
  };

  const inspectToolSpec = async (toolName: string) => {
    const res = await apiJson<Record<string, unknown>>(
      `/api/arsenal/tool/${encodeURIComponent(toolName)}`
    );
    setInspectedTool({
      name: toolName,
      detail: res.data || { error: res.error || t("common.noData") },
    });
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

  const resolveWordlist = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!wordlistQuery.trim()) return;
    const res = await apiJson<{ results?: Array<Record<string, unknown>>; matches?: Array<Record<string, unknown>> }>(
      `/api/wordlists/resolve?q=${encodeURIComponent(wordlistQuery.trim())}`
    );
    if (res.ok && res.data) {
      const list = Array.isArray(res.data.results)
        ? res.data.results
        : Array.isArray(res.data.matches)
          ? res.data.matches
          : [res.data as unknown as Record<string, unknown>];
      setWordlistMatches(list);
    } else {
      setWordlistMatches([{ error: res.error || t("common.noData") }]);
    }
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

  const filteredSkills = useMemo(() => {
    const q = skillFilter.trim().toLowerCase();
    return skills.filter(
      (s) =>
        !q ||
        s.name.toLowerCase().includes(q) ||
        (s.category || "").toLowerCase().includes(q) ||
        (s.description || "").toLowerCase().includes(q)
    );
  }, [skills, skillFilter]);

  const skillTotalPages = Math.max(1, Math.ceil(filteredSkills.length / SKILLS_PAGE_SIZE));
  const safeSkillPage = Math.min(skillPage, skillTotalPages);
  const pagedSkills = useMemo(() => {
    const start = (safeSkillPage - 1) * SKILLS_PAGE_SIZE;
    return filteredSkills.slice(start, start + SKILLS_PAGE_SIZE);
  }, [filteredSkills, safeSkillPage]);

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
            <span className="text-xs font-mono text-ink-muted tabular-nums">{agents.length}</span>
          </div>

          <div className="space-y-1.5 max-h-72 overflow-y-auto pe-1">
            {agents.map((ag, idx) => (
              <button
                key={`${ag.id || ag.name || "agent"}-${idx}`}
                type="button"
                onClick={() => setSelectedAgentId(ag.id)}
                className={`w-full p-2.5 rounded border text-start text-xs space-y-1 transition-colors ${
                  selectedAgentId === ag.id
                    ? "bg-sentinel-ai/15 border-sentinel-ai text-ink-primary"
                    : "bg-elevated border-border-subtle hover:border-border-strong text-ink-secondary"
                }`}
              >
                <div className="flex items-center justify-between gap-2">
                  <span className="font-mono font-semibold text-ink-primary">{ag.name}</span>
                  <span className="text-[10px] font-mono text-sentinel-success uppercase">{ag.status}</span>
                </div>
                <div className="text-[11px] text-ink-muted line-clamp-2">{ag.description}</div>
              </button>
            ))}
          </div>
        </section>

        <section className="lg:col-span-7 sentinel-surface p-4 flex flex-col gap-3">
          <div className="flex items-center justify-between pb-2 border-b border-border-subtle">
            <span className="text-sm font-semibold text-ink-primary">
              {t("arsenal.directChatTitle")} ({selectedAgentId || t("arsenal.noneSelected")})
            </span>
          </div>

          <form onSubmit={sendAgentInstruction} className="flex gap-2 text-xs">
            <input
              type="text"
              value={agentPrompt}
              onChange={(e) => setAgentPrompt(e.target.value)}
              placeholder={t("arsenal.agentPromptPlaceholder")}
              aria-label={t("arsenal.agentPromptPlaceholder")}
              className="flex-1 h-9 px-3 rounded bg-inset border border-border-subtle"
            />
            <button
              type="submit"
              disabled={agentSending || !selectedAgentId}
              className="min-h-[44px] sm:min-h-[36px] px-3.5 rounded bg-sentinel-primary text-sentinel-onAccent font-semibold flex items-center gap-1.5 disabled:opacity-50"
            >
              {agentSending ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Send className="w-3.5 h-3.5 rtl:rotate-180" />}
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
              {t("arsenal.selectAgentHint")}
            </div>
          )}
        </section>
      </div>

      {/* Paginated Skills Matrix + 6 Elite Exploit Probers */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-5">
        <section className="lg:col-span-7 sentinel-surface p-4 space-y-3">
          <div className="flex flex-wrap items-center justify-between gap-2 pb-2 border-b border-border-subtle">
            <div className="flex items-center gap-2">
              <Sparkles className="w-4 h-4 text-sentinel-primary" />
              <h2 className="text-sm font-semibold text-ink-primary">
                {t("sections.skills")} ({filteredSkills.length})
              </h2>
            </div>
            <input
              type="search"
              value={skillFilter}
              onChange={(e) => {
                setSkillFilter(e.target.value);
                setSkillPage(1);
              }}
              placeholder={t("common.search")}
              aria-label={t("common.search")}
              className="h-8 px-2.5 rounded bg-inset border border-border-subtle text-xs"
            />
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 max-h-64 overflow-y-auto pe-1">
            {pagedSkills.map((sk, idx) => (
              <div
                key={`${sk.name || "skill"}-${sk.layer || sk.category || ""}-${idx}`}
                className="p-2.5 rounded bg-elevated border border-border-subtle text-xs space-y-1"
              >
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

          {skillTotalPages > 1 && (
            <div className="flex items-center justify-between gap-2 pt-1 border-t border-border-subtle text-xs">
              <span className="font-mono text-ink-muted tabular-nums">
                {t("graph.pageOf", { page: safeSkillPage, total: skillTotalPages })}
              </span>
              <div className="flex items-center gap-1.5">
                <button
                  type="button"
                  disabled={safeSkillPage <= 1}
                  onClick={() => setSkillPage((p) => Math.max(1, p - 1))}
                  className="h-7 px-2 rounded border border-border-subtle bg-elevated text-ink-primary disabled:opacity-40 flex items-center gap-1"
                >
                  <ChevronLeft className="w-3.5 h-3.5 rtl:rotate-180" />
                  <span>{t("graph.prevPage")}</span>
                </button>
                <button
                  type="button"
                  disabled={safeSkillPage >= skillTotalPages}
                  onClick={() => setSkillPage((p) => Math.min(skillTotalPages, p + 1))}
                  className="h-7 px-2 rounded border border-border-subtle bg-elevated text-ink-primary disabled:opacity-40 flex items-center gap-1"
                >
                  <span>{t("graph.nextPage")}</span>
                  <ChevronRight className="w-3.5 h-3.5 rtl:rotate-180" />
                </button>
              </div>
            </div>
          )}
        </section>

        <section className="lg:col-span-5 sentinel-surface p-4 space-y-3">
          <div className="flex items-center gap-2 pb-2 border-b border-border-subtle">
            <Play className="w-4 h-4 text-sentinel-danger" />
            <h2 className="text-sm font-semibold text-ink-primary">{t("arsenal.eliteProbersTitle")}</h2>
          </div>

          <form onSubmit={runEliteProber} className="space-y-2 text-xs">
            <select
              value={eliteSkill}
              onChange={(e) => setEliteSkill(e.target.value)}
              aria-label={t("arsenal.eliteProbersTitle")}
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
                aria-label={t("common.target")}
                className="ltr-isolate flex-1 h-9 px-3 rounded bg-inset border border-border-subtle font-mono"
              />
              <button
                type="submit"
                className="min-h-[44px] sm:min-h-[36px] px-3 rounded bg-sentinel-primary text-sentinel-onAccent font-semibold"
              >
                {t("common.run")}
              </button>
            </div>
          </form>

          {eliteResult && (
            <pre dir="ltr" className="ltr-isolate p-2.5 rounded bg-inset border border-border-subtle font-mono text-[11px] max-h-40 overflow-auto">
              {sanitizePlainTerminalText(JSON.stringify(eliteResult, null, 2))}
            </pre>
          )}

          {/* Cognitive Wordlist Explorer */}
          <div className="pt-2 border-t border-border-subtle space-y-2">
            <div className="flex items-center justify-between gap-2 text-xs">
              <span className="font-semibold text-ink-secondary flex items-center gap-1.5">
                <BookOpen className="w-3.5 h-3.5 text-sentinel-primary" />
                <span>{t("arsenal.wordlistTitle")}</span>
              </span>
              <span className="font-mono text-[10px] text-ink-muted tabular-nums">
                {wordlistRoots.length} {t("arsenal.wordlistRoots")}
              </span>
            </div>
            <form onSubmit={resolveWordlist} className="flex gap-2 text-xs">
              <input
                type="text"
                value={wordlistQuery}
                onChange={(e) => setWordlistQuery(e.target.value)}
                placeholder={t("arsenal.wordlistPlaceholder")}
                aria-label={t("arsenal.wordlistPlaceholder")}
                className="flex-1 h-8 px-2.5 rounded bg-inset border border-border-subtle"
              />
              <button type="submit" className="h-8 px-2.5 rounded bg-elevated border border-border-strong font-semibold">
                {t("common.search")}
              </button>
            </form>
            {wordlistMatches.length > 0 && (
              <pre dir="ltr" className="ltr-isolate p-2 rounded bg-inset border border-border-subtle font-mono text-[10px] max-h-28 overflow-auto">
                {sanitizePlainTerminalText(JSON.stringify(wordlistMatches, null, 2))}
              </pre>
            )}
          </div>
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
              aria-label={t("tools.searchToolsPlaceholder")}
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
                {filteredTools.map((tl, idx) => (
                  <tr key={`${tl.name || "tool"}-${idx}`} className="ltr-isolate hover:bg-elevated/50">
                    <td className="py-1.5 px-3">
                      <button
                        type="button"
                        onClick={() => void inspectToolSpec(tl.name)}
                        className="text-sentinel-primary hover:underline text-start"
                      >
                        {tl.name}
                      </button>
                    </td>
                    <td className="py-1.5 px-3">
                      <span className={tl.installed ? "text-sentinel-success" : "text-ink-muted"}>
                        {tl.installed ? t("arsenal.toolInstalled") : t("states.missing")}
                      </span>
                    </td>
                    <td className="py-1.5 px-3">
                      <button
                        type="button"
                        disabled={testingToolName === tl.name}
                        onClick={() => void testTool(tl.name)}
                        className="px-2 py-0.5 rounded bg-elevated border border-border-subtle hover:border-sentinel-primary disabled:opacity-40"
                      >
                        {testingToolName === tl.name ? t("states.checking") : t("tools.checkHealth")}
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          {toolTestResult && (
            <div
              data-testid="tool-test-result"
              className={`p-3 rounded border text-xs space-y-1.5 ${
                toolTestResult.ok
                  ? "border-sentinel-success/40 bg-sentinel-success/10"
                  : "border-sentinel-danger/40 bg-sentinel-danger/10"
              }`}
            >
              <div className="flex items-center justify-between gap-2 font-mono font-semibold">
                <span className="flex items-center gap-1.5">
                  {toolTestResult.ok ? (
                    <CheckCircle2 className="w-3.5 h-3.5 text-sentinel-success" />
                  ) : (
                    <AlertCircle className="w-3.5 h-3.5 text-sentinel-danger" />
                  )}
                  <span className={toolTestResult.ok ? "text-sentinel-success" : "text-sentinel-danger"}>
                    {toolTestResult.toolName} · {toolTestResult.status}
                  </span>
                </span>
                {typeof toolTestResult.returncode === "number" && (
                  <span className="text-ink-muted tabular-nums">exit={toolTestResult.returncode}</span>
                )}
              </div>
              {toolTestResult.stdout && (
                <pre dir="ltr" className="ltr-isolate p-2 rounded bg-inset border border-border-subtle font-mono text-[11px] text-ink-primary max-h-24 overflow-auto">
                  {sanitizePlainTerminalText(toolTestResult.stdout)}
                </pre>
              )}
              {toolTestResult.stderr && (
                <pre dir="ltr" className="ltr-isolate p-2 rounded bg-inset border border-border-subtle font-mono text-[11px] text-sentinel-danger max-h-24 overflow-auto">
                  {sanitizePlainTerminalText(toolTestResult.stderr)}
                </pre>
              )}
            </div>
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
                aria-label={t("tools.colTool")}
                className="ltr-isolate h-8 px-2.5 rounded bg-inset border border-border-subtle font-mono"
              />
              <input
                type="text"
                dir="ltr"
                value={synthWaf}
                onChange={(e) => setSynthWaf(e.target.value)}
                placeholder={t("tools.wafLabel")}
                aria-label={t("tools.wafLabel")}
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
                aria-label={t("common.target")}
                className="ltr-isolate flex-1 h-8 px-2.5 rounded bg-inset border border-border-subtle font-mono"
              />
              <button type="submit" className="h-8 px-3 rounded bg-sentinel-primary text-sentinel-onAccent font-semibold">
                {t("arsenal.synthesizeBtn")}
              </button>
            </div>
          </form>

          {synthResult && (
            <pre dir="ltr" className="ltr-isolate p-2.5 rounded bg-inset border border-border-subtle font-mono text-[11px] max-h-40 overflow-auto">
              {sanitizePlainTerminalText(JSON.stringify(synthResult, null, 2))}
            </pre>
          )}
        </section>
      </div>

      {/* Structured MCP Manager Modal & Cards */}
      <McpManagerModal />

      {/* CLI Engines & Local Sandbox */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">
        <section className="sentinel-surface p-4 space-y-3">
          <div className="flex items-center justify-between pb-2 border-b border-border-subtle">
            <div className="flex items-center gap-2">
              <Cpu className="w-4 h-4 text-sentinel-primary" />
              <h2 className="text-sm font-semibold text-ink-primary">{t("arsenal.cliEnginesTitle")}</h2>
            </div>
            <button
              type="button"
              onClick={() => void runEngineSelfcheck()}
              className="h-7 px-2 rounded border border-border-subtle bg-elevated text-xs font-mono"
            >
              {t("arsenal.selfcheckBtn")}
            </button>
          </div>
          <div className="space-y-1.5 text-xs">
            {engines.map((e, idx) => (
              <div key={`${e.engine || e.display_name || "engine"}-${idx}`} className="p-2 rounded bg-elevated border border-border-subtle font-mono flex justify-between">
                <span>{e.display_name || e.engine}</span>
                <span className="text-ink-muted">{e.supports_streaming ? "STREAM" : "SYNC"}</span>
              </div>
            ))}
          </div>
          {selfcheckOut && (
            <pre dir="ltr" className="ltr-isolate p-2 rounded bg-inset border border-border-subtle font-mono text-[10px] max-h-32 overflow-auto">
              {sanitizePlainTerminalText(JSON.stringify(selfcheckOut, null, 2))}
            </pre>
          )}
        </section>

        <section className="sentinel-surface p-4 space-y-3">
          <div className="flex items-center justify-between pb-2 border-b border-border-subtle">
            <div className="flex items-center gap-2">
              <Box className="w-4 h-4 text-sentinel-ai" />
              <h2 className="text-sm font-semibold text-ink-primary">{t("arsenal.sandboxTitle")}</h2>
            </div>
            <span className={`font-mono text-xs ${sandboxStatus?.ok ? "text-sentinel-success" : "text-sentinel-warning"}`}>
              {sandboxStatus?.ok ? t("states.ready") : t("states.checking")}
            </span>
          </div>
          <form onSubmit={runSandbox} className="flex gap-2 text-xs">
            <input
              type="text"
              dir="ltr"
              value={sandboxCmd}
              onChange={(e) => setSandboxCmd(e.target.value)}
              aria-label={t("arsenal.sandboxTitle")}
              className="ltr-isolate flex-1 h-8 px-2.5 rounded bg-inset border border-border-subtle font-mono"
            />
            <button type="submit" className="h-8 px-3 rounded bg-elevated border border-border-strong font-semibold">
              {t("common.run")}
            </button>
          </form>
          {sandboxOut && (
            <pre dir="ltr" className="ltr-isolate p-2 rounded bg-inset border border-border-subtle font-mono text-[11px] max-h-40 overflow-auto">
              {sanitizePlainTerminalText(JSON.stringify(sandboxOut, null, 2))}
            </pre>
          )}
        </section>
      </div>

      {/* Tool Spec Inspector Modal */}
      {inspectedTool && (
        <div
          className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/60 backdrop-blur-[1px]"
          onClick={() => setInspectedTool(null)}
        >
          <div
            ref={toolModalTrapRef}
            role="dialog"
            aria-modal="true"
            aria-label={inspectedTool.name}
            tabIndex={-1}
            onClick={(e) => e.stopPropagation()}
            className="w-full max-w-2xl max-h-[80vh] bg-surface border border-border-strong rounded-xl shadow-sentinelMd flex flex-col overflow-hidden"
          >
            <div className="px-4 py-3 border-b border-border-subtle flex items-center justify-between">
              <h3 className="text-sm font-semibold font-mono text-ink-primary ltr-isolate">
                {inspectedTool.name}
              </h3>
              <button
                type="button"
                onClick={() => setInspectedTool(null)}
                aria-label={t("common.close")}
                className="h-8 w-8 rounded border border-border-subtle bg-elevated text-ink-primary flex items-center justify-center"
              >
                <X className="w-4 h-4" />
              </button>
            </div>
            <pre dir="ltr" className="ltr-isolate flex-1 overflow-auto p-4 font-mono text-[11px] text-ink-secondary">
              {sanitizePlainTerminalText(JSON.stringify(inspectedTool.detail, null, 2))}
            </pre>
          </div>
        </div>
      )}
    </div>
  );
}
