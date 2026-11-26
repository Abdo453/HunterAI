"use client";

import React, { useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  Files,
  Sparkles,
  Shield,
  Wrench,
  Save,
  Plus,
  Play,
  Send,
  Copy,
  Check,
  X,
  Terminal,
  ChevronDown,
  ChevronUp,
  ChevronRight,
  RefreshCw,
  Folder,
  FolderOpen,
  FileCode,
  Loader2,
  ShieldAlert,
  AlertTriangle,
} from "lucide-react";
import {
  BurpStatusResponse,
  BurpTrafficItem,
  EditorTreeItem,
  StaticAuditResponse,
} from "@/lib/api-types";
import { usePlatform } from "@/lib/platform-context";
import { useTheme } from "@/lib/theme";
import { useI18n } from "@/lib/i18n";
import { renderSafeMarkdown } from "@/lib/sanitize";
import { sanitizePlainTerminalText } from "@/lib/terminal-sanitizer";
import { useUnsavedChangesGuard } from "@/hooks/use-unsaved-changes-guard";
import { useFocusTrap } from "@/hooks/use-focus-trap";

interface SkillSummary {
  name: string;
  pack?: string;
  kind?: string;
  description?: string;
}

interface StudioTab {
  id: string;
  name: string;
  path: string;
  isSpecial?: boolean;
  isSkill?: boolean;
  skillName?: string;
  content: string;
  extension: string;
  dirty?: boolean;
}

interface MonacoModel {
  dispose: () => void;
  getValue: () => string;
}

interface MonacoEditorInstance {
  getValue: () => string;
  getModel: () => MonacoModel | null;
  setModel: (model: MonacoModel) => void;
  onDidChangeModelContent: (cb: () => void) => { dispose: () => void };
  addCommand: (keybinding: number, handler: () => void) => void;
  dispose: () => void;
}

interface MonacoNamespace {
  KeyMod: { CtrlCmd: number };
  KeyCode: { KeyS: number; Enter: number };
  editor: {
    create: (el: HTMLElement, options: Record<string, unknown>) => MonacoEditorInstance;
    createModel: (value: string, language: string) => MonacoModel;
    setTheme: (theme: string) => void;
  };
}

interface AmdRequire {
  (deps: string[], cb: () => void): void;
  config: (cfg: { paths: Record<string, string> }) => void;
}

type WindowWithMonaco = Window & {
  require?: AmdRequire;
  monaco?: MonacoNamespace;
};

interface FolderTreeNode {
  name: string;
  path: string;
  isDir: boolean;
  children: FolderTreeNode[];
}

function isDirectoryItem(item: EditorTreeItem): boolean {
  const norm = String(item.type || "").toLowerCase();
  return Boolean(item.is_dir) || norm === "dir" || norm === "directory";
}

function buildHierarchyTree(items: EditorTreeItem[]): FolderTreeNode[] {
  const rootMap = new Map<string, FolderTreeNode>();
  const ensureNode = (path: string, isDir: boolean, explicitName?: string): FolderTreeNode => {
    const clean = path.replace(/^\/+|\/+$/g, "");
    const existing = rootMap.get(clean);
    if (existing) {
      if (isDir) existing.isDir = true;
      return existing;
    }
    const parts = clean.split("/");
    const name = explicitName || parts[parts.length - 1] || clean;
    const node: FolderTreeNode = { name, path: clean, isDir, children: [] };
    rootMap.set(clean, node);
    if (parts.length > 1) {
      const parentPath = parts.slice(0, -1).join("/");
      const parent = ensureNode(parentPath, true);
      if (!parent.children.some((c) => c.path === clean)) {
        parent.children.push(node);
      }
    }
    return node;
  };

  for (const item of items) {
    if (!item.path) continue;
    ensureNode(item.path, isDirectoryItem(item), item.name);
  }

  const sortTree = (nodes: FolderTreeNode[]): FolderTreeNode[] =>
    nodes
      .sort((a, b) => {
        if (a.isDir !== b.isDir) return a.isDir ? -1 : 1;
        return a.name.localeCompare(b.name);
      })
      .map((n) => ({ ...n, children: sortTree(n.children) }));

  const topLevel = Array.from(rootMap.values()).filter((n) => !n.path.includes("/"));
  return sortTree(topLevel);
}

const EXT_TO_LANG: Record<string, string> = {
  py: "python",
  js: "javascript",
  mjs: "javascript",
  cjs: "javascript",
  ts: "typescript",
  tsx: "typescript",
  jsx: "javascript",
  json: "json",
  md: "markdown",
  html: "html",
  css: "css",
  yaml: "yaml",
  yml: "yaml",
  sh: "shell",
  sql: "sql",
  go: "go",
  rs: "rust",
};

const REPEATER_PRESETS: Record<string, { url: string; raw: string }> = {
  get: {
    url: "https://example.com/",
    raw: "GET / HTTP/1.1\nHost: example.com\nUser-Agent: HunterAI-Studio/2.0\nAccept: text/html,application/json\n\n",
  },
  post_json: {
    url: "https://example.com/api/v1/login",
    raw: 'POST /api/v1/login HTTP/1.1\nHost: example.com\nContent-Type: application/json\n\n{\n  "username": "test",\n  "password": "test"\n}',
  },
  idor: {
    url: "https://example.com/api/orders?id=1002",
    raw: "GET /api/orders?id=1002 HTTP/1.1\nHost: example.com\nAccept: application/json\n\n",
  },
};

export default function StudioPage() {
  const {
    selectedEngagement,
    selectedEngagementId,
    repeaterDraft,
    setRepeaterDraft,
    studioOpenPath,
    setStudioOpenPath,
    apiJson,
  } = usePlatform();
  const { theme } = useTheme();
  const { t } = useI18n();

  const [activityTab, setActivityTab] = useState<"explorer" | "skills" | "burp" | "sast" | "tools">("explorer");
  const [treeItems, setTreeItems] = useState<EditorTreeItem[]>([]);
  const [expandedDirs, setExpandedDirs] = useState<Record<string, boolean>>({});
  const [loadedDirs, setLoadedDirs] = useState<Record<string, boolean>>({});
  const [fileFilter, setFileFilter] = useState<string>("");
  const [newFilePath, setNewFilePath] = useState<string>("");

  const [skills, setSkills] = useState<SkillSummary[]>([]);
  const [skillFilter, setSkillFilter] = useState<string>("");
  const [traffic, setTraffic] = useState<BurpTrafficItem[]>([]);
  const [burpProxyOnline, setBurpProxyOnline] = useState<boolean>(false);
  const [tools, setTools] = useState<Array<{ name: string; installed: boolean }>>([]);

  // CodeIntel SAST State
  const [sastCode, setSastCode] = useState<string>("");
  const [sastRunning, setSastRunning] = useState<boolean>(false);
  const [sastResult, setSastResult] = useState<StaticAuditResponse | null>(null);

  const [tabs, setTabs] = useState<StudioTab[]>([
    {
      id: "special:repeater",
      name: "Burp Repeater",
      path: "special:repeater",
      isSpecial: true,
      content: "",
      extension: "http",
    },
  ]);
  const [activeTabId, setActiveTabId] = useState<string>("special:repeater");
  const [monacoReady, setMonacoReady] = useState<boolean>(false);
  const [statusNotice, setStatusNotice] = useState<string>("");

  // Burp Repeater State
  const [repUrl, setRepUrl] = useState<string>("");
  const [repRaw, setRepRaw] = useState<string>(REPEATER_PRESETS.get.raw);
  const [repUseProxy, setRepUseProxy] = useState<boolean>(false);
  const [repResponse, setRepResponse] = useState<string>("");
  const [repStatusMeta, setRepStatusMeta] = useState<string>("");
  const [repSending, setRepSending] = useState<boolean>(false);
  const [repAuditMd, setRepAuditMd] = useState<string>("");
  const [repAuditing, setRepAuditing] = useState<boolean>(false);
  const [copiedResp, setCopiedResp] = useState<boolean>(false);

  // Bottom Dock State
  const [dockOpen, setDockOpen] = useState<boolean>(true);
  const [dockTab, setDockTab] = useState<"term" | "burp">("term");
  const [termCmd, setTermCmd] = useState<string>("");
  const [dockLogs, setDockLogs] = useState<string[]>([
    "[*] Security Studio ready. Self-hosted Monaco + Burp Repeater + CodeIntel SAST + Terminal.",
  ]);
  const [sensoryEvents, setSensoryEvents] = useState<Array<Record<string, unknown>>>([]);

  const monacoContainerRef = useRef<HTMLDivElement | null>(null);
  const editorRef = useRef<MonacoEditorInstance | null>(null);
  const modelCacheRef = useRef<Map<string, MonacoModel>>(new Map());
  const activeTabRef = useRef<string>(activeTabId);
  const tabsRef = useRef<StudioTab[]>(tabs);
  const syncingModelRef = useRef<boolean>(false);

  const hasDirtyTabs = useMemo(() => tabs.some((tb) => Boolean(tb.dirty)), [tabs]);
  const unsavedGuard = useUnsavedChangesGuard({
    isDirty: hasDirtyTabs,
    message: t("studio.unsavedWarning"),
  });
  const discardModalTrapRef = useFocusTrap(unsavedGuard.hasPendingPrompt, unsavedGuard.cancelDiscard);

  useEffect(() => {
    activeTabRef.current = activeTabId;
  }, [activeTabId]);

  useEffect(() => {
    tabsRef.current = tabs;
  }, [tabs]);

  const appendDock = useCallback((line: string) => {
    const clean = sanitizePlainTerminalText(line);
    setDockLogs((prev) => [...prev.slice(-199), clean]);
  }, []);

  // Load Sidebar Data
  const loadSidebarData = useCallback(async () => {
    const [treeR, skR, burpStR, burpTrR, toolsR, sensR] = await Promise.all([
      apiJson<{ items?: EditorTreeItem[]; entries?: EditorTreeItem[] }>("/api/editor/tree"),
      apiJson<{ skills?: SkillSummary[] }>("/api/opencode/skills"),
      apiJson<BurpStatusResponse>("/api/burp/status"),
      apiJson<{ items?: BurpTrafficItem[]; traffic?: BurpTrafficItem[] }>("/api/burp/traffic?limit=30"),
      apiJson<{ tools?: Array<{ name: string; installed: boolean } | string> }>("/api/control/tools"),
      apiJson<{ events?: Array<Record<string, unknown>> }>("/api/burp/sensory_events"),
    ]);
    const rawTree = Array.isArray(treeR.data?.items)
      ? treeR.data.items
      : Array.isArray(treeR.data?.entries)
        ? treeR.data.entries
        : null;
    if (treeR.ok && rawTree) {
      setTreeItems(
        rawTree
          .filter((it): it is EditorTreeItem => Boolean(it && typeof it === "object" && it.path))
          .map((it) => ({
            type: isDirectoryItem(it) ? "directory" : "file",
            is_dir: isDirectoryItem(it),
            name: String(it.name || it.path),
            path: String(it.path),
            ext: it.ext,
            parent: it.parent,
          }))
      );
    }
    if (skR.ok && Array.isArray(skR.data?.skills)) setSkills(skR.data.skills);
    if (burpStR.ok && burpStR.data?.proxy) {
      setBurpProxyOnline(
        Boolean(
          burpStR.data.proxy.reachable ||
            burpStR.data.proxy.online ||
            burpStR.data.proxy.status === "online"
        )
      );
    }
    if (burpTrR.ok && burpTrR.data) {
      const list = Array.isArray(burpTrR.data.items)
        ? burpTrR.data.items
        : Array.isArray(burpTrR.data.traffic)
          ? burpTrR.data.traffic
          : [];
      setTraffic(list);
    }
    if (toolsR.ok && Array.isArray(toolsR.data?.tools)) {
      setTools(
        toolsR.data.tools
          .map((tl: unknown) => {
            if (typeof tl === "string" && tl) return { name: tl, installed: true };
            if (tl && typeof tl === "object") {
              const obj = tl as Record<string, unknown>;
              const name = String(obj.name || "");
              if (!name) return null;
              return { name, installed: Boolean(obj.installed ?? true) };
            }
            return null;
          })
          .filter((tl): tl is { name: string; installed: boolean } => tl !== null)
      );
    }
    if (sensR.ok && Array.isArray(sensR.data?.events)) setSensoryEvents(sensR.data.events);
  }, [apiJson]);

  useEffect(() => {
    void loadSidebarData();
  }, [loadSidebarData]);

  // Expand/collapse folder lazily without ever calling /api/editor/file on a directory
  const toggleDirectory = async (dirPath: string) => {
    const nextOpen = !expandedDirs[dirPath];
    setExpandedDirs((prev) => ({ ...prev, [dirPath]: nextOpen }));
    if (nextOpen && !loadedDirs[dirPath]) {
      setLoadedDirs((prev) => ({ ...prev, [dirPath]: true }));
      const res = await apiJson<{ items?: EditorTreeItem[]; entries?: EditorTreeItem[] }>(
        `/api/editor/tree?folder=${encodeURIComponent(dirPath)}`
      );
      const rawChildren = Array.isArray(res.data?.items)
        ? res.data.items
        : Array.isArray(res.data?.entries)
          ? res.data.entries
          : [];
      if (res.ok && rawChildren.length > 0) {
        setTreeItems((prev) => {
          const existing = new Set(prev.map((p) => p.path));
          const additions: EditorTreeItem[] = [];
          for (const child of rawChildren) {
            if (!child?.path || existing.has(child.path)) continue;
            existing.add(child.path);
            additions.push({
              type: isDirectoryItem(child) ? "directory" : "file",
              is_dir: isDirectoryItem(child),
              name: String(child.name || child.path),
              path: String(child.path),
              ext: child.ext,
              parent: child.parent,
            });
          }
          return additions.length > 0 ? [...prev, ...additions] : prev;
        });
      }
    }
  };

  // Open workspace file or SKILL.md in a Monaco tab
  const openFileTab = useCallback(
    async (path: string, opts?: { isSkill?: boolean; skillName?: string }) => {
      const existing = tabsRef.current.find((tb) => tb.id === path);
      if (existing) {
        setActiveTabId(path);
        return;
      }

      const url =
        opts?.isSkill && opts.skillName
          ? `/api/opencode/skill-file?name=${encodeURIComponent(opts.skillName)}`
          : `/api/editor/file?path=${encodeURIComponent(path)}`;
      const res = await apiJson<{ status?: string; content?: string; path?: string; extension?: string }>(url);
      if (!res.ok || !res.data) {
        setStatusNotice(res.error || t("studio.readFailed"));
        return;
      }
      const actualPath = res.data.path || path;
      const ext = (res.data.extension || actualPath.split(".").pop() || "txt").replace(/^\./, "").toLowerCase();
      const name = actualPath.split("/").pop() || actualPath;
      const nextTab: StudioTab = {
        id: actualPath,
        name,
        path: actualPath,
        isSkill: opts?.isSkill,
        skillName: opts?.skillName,
        content: res.data.content || "",
        extension: ext,
        dirty: false,
      };
      setTabs((prev) => (prev.some((tb) => tb.id === actualPath) ? prev : [...prev, nextTab]));
      setActiveTabId(actualPath);
    },
    [apiJson, t]
  );

  // Honor ?tab=repeater, ?file=..., studioOpenPath (Copilot file ref), and repeaterDraft
  useEffect(() => {
    try {
      const params = new URLSearchParams(window.location.search);
      if (params.get("tab") === "repeater") {
        setActiveTabId("special:repeater");
      }
      const fileParam = params.get("file");
      if (fileParam) {
        void openFileTab(fileParam);
      }
    } catch {
      // Ignore URL errors
    }
    if (repeaterDraft) {
      setRepRaw(repeaterDraft.rawRequest);
      if (repeaterDraft.targetUrl) setRepUrl(repeaterDraft.targetUrl);
      if (typeof repeaterDraft.useProxy === "boolean") setRepUseProxy(repeaterDraft.useProxy);
      setActiveTabId("special:repeater");
      setRepeaterDraft(null);
    }
    if (studioOpenPath) {
      const targetPath = studioOpenPath;
      setStudioOpenPath(null);
      void openFileTab(targetPath);
    }
  }, [repeaterDraft, setRepeaterDraft, studioOpenPath, setStudioOpenPath, openFileTab]);

  const saveTab = useCallback(
    async (tabId?: string) => {
      const id = tabId || activeTabRef.current;
      const current = tabsRef.current.find((tb) => tb.id === id);
      if (!current || current.isSpecial) return;

      const cachedModel = modelCacheRef.current.get(id);
      const content =
        cachedModel
          ? cachedModel.getValue()
          : id === activeTabRef.current && editorRef.current
            ? editorRef.current.getValue()
            : current.content;

      const res =
        current.isSkill && current.skillName
          ? await apiJson<{ status?: string }>("/api/opencode/skill-file/save", {
              method: "POST",
              body: { name: current.skillName, path: current.path, content },
            })
          : await apiJson<{ status?: string }>("/api/editor/file/save", {
              method: "POST",
              body: { path: current.path, content },
            });

      if (!res.ok) {
        setStatusNotice(`${t("studio.saveFailed")}${res.error || ""}`);
        return;
      }
      setTabs((prev) =>
        prev.map((tb) => (tb.id === id ? { ...tb, content, dirty: false } : tb))
      );
      setStatusNotice(`${t("studio.savedFile")}${current.path}`);
    },
    [apiJson, t]
  );

  // Dynamically load self-hosted Monaco AMD loader from /vendor/monaco/vs
  useEffect(() => {
    let cancelled = false;
    const win = window as unknown as WindowWithMonaco;

    const initEditor = () => {
      if (cancelled || !monacoContainerRef.current || !win.require) return;
      win.require.config({ paths: { vs: "/vendor/monaco/vs" } });
      win.require(["vs/editor/editor.main"], () => {
        if (cancelled || !monacoContainerRef.current || !win.monaco) return;
        const editor = win.monaco.editor.create(monacoContainerRef.current, {
          value: "# HunterAI Security Studio\n",
          language: "python",
          theme: theme === "light" ? "vs" : "vs-dark",
          automaticLayout: true,
          fontSize: 13,
          fontFamily: "'JetBrains Mono', ui-monospace, monospace",
          minimap: { enabled: true },
          scrollBeyondLastLine: false,
        });
        editor.onDidChangeModelContent(() => {
          if (syncingModelRef.current) return;
          const curId = activeTabRef.current;
          if (!curId || curId.startsWith("special:")) return;
          const val = editor.getValue();
          setTabs((prev) =>
            prev.map((tb) => (tb.id === curId ? { ...tb, content: val, dirty: true } : tb))
          );
        });
        editor.addCommand(win.monaco.KeyMod.CtrlCmd | win.monaco.KeyCode.KeyS, () => {
          void saveTab();
        });
        editorRef.current = editor;
        setMonacoReady(true);
      });
    };

    if (win.monaco || win.require) {
      initEditor();
    } else {
      const existing = document.querySelector<HTMLScriptElement>('script[data-monaco-loader="1"]');
      if (existing) {
        existing.addEventListener("load", initEditor, { once: true });
      } else {
        const script = document.createElement("script");
        script.src = "/vendor/monaco/vs/loader.min.js";
        script.async = true;
        script.dataset.monacoLoader = "1";
        script.addEventListener("load", initEditor, { once: true });
        script.addEventListener(
          "error",
          () => appendDock("[!] Failed to load self-hosted Monaco loader."),
          { once: true }
        );
        document.body.appendChild(script);
      }
    }

    const cache = modelCacheRef.current;
    return () => {
      cancelled = true;
      for (const model of cache.values()) {
        model.dispose();
      }
      cache.clear();
      if (editorRef.current) {
        editorRef.current.dispose();
        editorRef.current = null;
      }
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // Keep Monaco theme synchronized with Obsidian Sentinel / Paper Slate
  useEffect(() => {
    const win = window as unknown as WindowWithMonaco;
    if (win.monaco?.editor) {
      win.monaco.editor.setTheme(theme === "light" ? "vs" : "vs-dark");
    }
  }, [theme]);

  const activeTab = useMemo(
    () => tabs.find((tb) => tb.id === activeTabId) || tabs[0],
    [tabs, activeTabId]
  );

  // Per-tab Monaco model cache preserves undo/redo buffers across tab switches
  useEffect(() => {
    if (!monacoReady || !editorRef.current || !activeTab || activeTab.isSpecial) return;
    const win = window as unknown as WindowWithMonaco;
    if (!win.monaco?.editor) return;

    let cached = modelCacheRef.current.get(activeTab.id);
    if (!cached) {
      const langId = EXT_TO_LANG[activeTab.extension] || "plaintext";
      cached = win.monaco.editor.createModel(activeTab.content || "", langId);
      modelCacheRef.current.set(activeTab.id, cached);
    }
    syncingModelRef.current = true;
    try {
      editorRef.current.setModel(cached);
    } finally {
      syncingModelRef.current = false;
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [activeTabId, monacoReady]);

  const handleCreateFile = async (e: React.FormEvent) => {
    e.preventDefault();
    const clean = newFilePath.trim();
    if (!clean) return;
    const res = await apiJson("/api/editor/file/create", {
      method: "POST",
      body: { path: clean, type: "file", content: "# Created in Security Studio\n" },
    });
    if (!res.ok) {
      setStatusNotice(res.error || t("studio.saveFailed"));
      return;
    }
    setNewFilePath("");
    await loadSidebarData();
    await openFileTab(clean);
  };

  const performCloseTab = (id: string) => {
    if (id === "special:repeater") return;
    const cached = modelCacheRef.current.get(id);
    if (cached) {
      modelCacheRef.current.delete(id);
      cached.dispose();
    }
    setTabs((prev) => {
      const next = prev.filter((tb) => tb.id !== id);
      if (activeTabId === id) {
        setActiveTabId(next[next.length - 1]?.id || "special:repeater");
      }
      return next;
    });
  };

  const closeTab = (tb: StudioTab) => {
    if (tb.isSpecial) return;
    if (tb.dirty) {
      unsavedGuard.requestAction(() => performCloseTab(tb.id));
      return;
    }
    performCloseTab(tb.id);
  };

  const runCodeIntelSast = async (e?: React.FormEvent) => {
    if (e) e.preventDefault();
    const sourceCode =
      sastCode.trim() ||
      (activeTab && !activeTab.isSpecial
        ? modelCacheRef.current.get(activeTab.id)?.getValue() || activeTab.content
        : "");
    if (!sourceCode.trim()) return;
    setSastRunning(true);
    setSastResult(null);
    const res = await apiJson<StaticAuditResponse>("/api/static/audit", {
      method: "POST",
      body: {
        source_code: sourceCode,
        target_name: activeTab && !activeTab.isSpecial ? activeTab.path : selectedEngagement?.target || "studio_snippet",
        context: selectedEngagement?.name || "Security Studio CodeIntel SAST",
      },
    });
    setSastRunning(false);
    setSastResult(res.data || { ok: false, error: res.error || t("common.error") });
  };

  const sendRepeater = async () => {
    if (!repRaw.trim()) return;
    setRepSending(true);
    setRepAuditMd("");
    setRepResponse(t("studio.sendingReq"));
    const res = await apiJson<{
      status?: string;
      status_code?: number;
      reason?: string;
      elapsed_ms?: number;
      bytes?: number;
      raw_response?: string;
      message?: string;
    }>("/api/burp/repeater/send", {
      method: "POST",
      body: {
        raw_request: repRaw,
        url: repUrl.trim(),
        use_proxy: repUseProxy,
      },
    });
    setRepSending(false);
    if (!res.ok || !res.data || res.data.status !== "ok") {
      setRepStatusMeta("ERR");
      setRepResponse(res.error || res.data?.message || t("common.error"));
      return;
    }
    setRepStatusMeta(`${res.data.status_code} ${res.data.reason || ""} · ${res.data.elapsed_ms}ms · ${res.data.bytes}B`);
    setRepResponse(res.data.raw_response || "");
    appendDock(`[HTTP] ${repRaw.split("\n")[0]} -> ${res.data.status_code} (${res.data.elapsed_ms}ms)`);
  };

  const auditRepeater = async () => {
    if (!repRaw.trim() || !repResponse.trim()) return;
    setRepAuditing(true);
    const res = await apiJson<{ analysis?: string }>("/api/burp/ai-audit", {
      method: "POST",
      body: { raw_request: repRaw, raw_response: repResponse, skill_category: "web-api-security" },
    });
    setRepAuditing(false);
    setRepAuditMd(res.ok ? res.data?.analysis || "" : res.error || t("common.error"));
  };

  const runTerminal = async (overrideCmd?: string) => {
    const cmd = (overrideCmd ?? termCmd).trim();
    if (!cmd) return;
    if (!overrideCmd) setTermCmd("");
    setDockOpen(true);
    setDockTab("term");
    appendDock(`$ ${cmd}`);
    const res = await apiJson<{ stdout?: string; output?: string; stderr?: string; error?: string; blocked?: boolean }>(
      "/api/run-tool",
      {
        method: "POST",
        body: {
          command: cmd,
          target: selectedEngagement?.target || undefined,
          scope: selectedEngagement?.in_scope?.length ? selectedEngagement.in_scope : undefined,
          out_of_scope: selectedEngagement?.out_of_scope?.length ? selectedEngagement.out_of_scope : undefined,
          engagement_id: selectedEngagementId || undefined,
        },
      }
    );
    const out = res.data?.stdout || res.data?.output || res.data?.stderr || res.error || res.data?.error || "";
    appendDock(out || `[HTTP ${res.status}]`);
  };

  const runSkillQuick = async (skillName: string) => {
    const tgt = selectedEngagement?.target || "example.com";
    setDockOpen(true);
    appendDock(`[+] Dispatching ${skillName} -> ${tgt}`);
    const res = await apiJson<{ job_id?: string; output?: string; message?: string }>("/api/opencode/execute", {
      method: "POST",
      body: { skill_name: skillName, target: tgt },
    });
    appendDock(res.ok ? `[OK] ${res.data?.job_id || "done"} ${res.data?.output || ""}` : `[!] ${res.error}`);
  };

  const hierarchyTree = useMemo(() => buildHierarchyTree(treeItems), [treeItems]);

  const filteredFlatTree = useMemo(() => {
    const q = fileFilter.trim().toLowerCase();
    if (!q) return [];
    return treeItems
      .filter((it) => !isDirectoryItem(it) && it.path.toLowerCase().includes(q))
      .slice(0, 200);
  }, [treeItems, fileFilter]);

  const filteredSkills = useMemo(() => {
    const q = skillFilter.trim().toLowerCase();
    return skills.filter(
      (s) => !q || s.name.toLowerCase().includes(q) || (s.description || "").toLowerCase().includes(q)
    );
  }, [skills, skillFilter]);

  const auditHtml = useMemo(() => (repAuditMd ? renderSafeMarkdown(repAuditMd) : ""), [repAuditMd]);

  const renderTreeNodes = (nodes: FolderTreeNode[], depth = 0): React.ReactNode =>
    nodes.map((node) => {
      const isOpen = Boolean(expandedDirs[node.path]);
      if (node.isDir) {
        return (
          <div key={node.path}>
            <button
              type="button"
              aria-expanded={isOpen}
              onClick={() => void toggleDirectory(node.path)}
              style={{ paddingInlineStart: `${8 + depth * 12}px` }}
              className="w-full pe-2 py-1 rounded text-start flex items-center gap-1.5 font-mono text-[11px] ltr-isolate hover:bg-elevated text-ink-secondary"
            >
              {isOpen ? (
                <ChevronDown className="w-3 h-3 shrink-0 text-ink-muted" />
              ) : (
                <ChevronRight className="w-3 h-3 shrink-0 text-ink-muted rtl:rotate-180" />
              )}
              {isOpen ? (
                <FolderOpen className="w-3.5 h-3.5 shrink-0 text-sentinel-warning" />
              ) : (
                <Folder className="w-3.5 h-3.5 shrink-0 text-sentinel-warning" />
              )}
              <span className="truncate">{node.name}</span>
            </button>
            {isOpen && node.children.length > 0 && (
              <div className="space-y-0.5">{renderTreeNodes(node.children, depth + 1)}</div>
            )}
          </div>
        );
      }
      return (
        <button
          key={node.path}
          type="button"
          onClick={() => void openFileTab(node.path)}
          style={{ paddingInlineStart: `${22 + depth * 12}px` }}
          className={`w-full pe-2 py-1 rounded text-start flex items-center gap-1.5 font-mono text-[11px] ltr-isolate truncate ${
            activeTabId === node.path
              ? "bg-sentinel-primary/15 text-sentinel-primary"
              : "hover:bg-elevated text-ink-secondary"
          }`}
        >
          <FileCode className="w-3.5 h-3.5 shrink-0 text-sentinel-primary" />
          <span className="truncate">{node.name}</span>
        </button>
      );
    });

  const sastFindings = Array.isArray(sastResult?.findings)
    ? sastResult.findings
    : Array.isArray(sastResult?.issues)
      ? sastResult.issues
      : [];

  return (
    <div className="flex-1 flex flex-col min-h-[calc(100vh-56px)] bg-canvas">
      {/* Studio Toolbar */}
      <div className="px-4 py-2 border-b border-border-subtle bg-surface flex flex-wrap items-center justify-between gap-2 text-xs">
        <div className="flex items-center gap-2">
          <h1 className="font-semibold text-ink-primary">{t("routes.studio")}</h1>
          {hasDirtyTabs && (
            <span className="font-mono text-[11px] px-2 py-0.5 rounded bg-sentinel-warning/15 text-sentinel-warning border border-sentinel-warning/35">
              {t("editor.modifiedBadge")}
            </span>
          )}
          {statusNotice && (
            <span className="font-mono text-sentinel-primary bg-sentinel-primary/15 px-2 py-0.5 rounded">
              {statusNotice}
            </span>
          )}
        </div>

        <div className="flex flex-wrap items-center gap-2">
          <button
            type="button"
            disabled={!activeTab || activeTab.isSpecial}
            onClick={() => void saveTab()}
            className="h-8 px-3 rounded border border-border-subtle bg-elevated hover:border-sentinel-primary text-ink-primary flex items-center gap-1.5 disabled:opacity-40"
          >
            <Save className="w-3.5 h-3.5 text-sentinel-success" />
            <span>{t("studio.save")}</span>
          </button>

          {activeTab && !activeTab.isSpecial && (
            <button
              type="button"
              disabled={sastRunning}
              onClick={() => {
                setActivityTab("sast");
                void runCodeIntelSast();
              }}
              className="h-8 px-3 rounded border border-sentinel-ai/40 bg-sentinel-ai/15 text-sentinel-ai font-semibold flex items-center gap-1.5 disabled:opacity-40"
            >
              {sastRunning ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <ShieldAlert className="w-3.5 h-3.5" />}
              <span>{t("studio.sastAuditBtn")}</span>
            </button>
          )}

          {activeTab && !activeTab.isSpecial && activeTab.extension === "py" && (
            <button
              type="button"
              onClick={() => void runTerminal(`python ${activeTab.path}`)}
              className="h-8 px-3 rounded border border-border-subtle bg-elevated hover:border-sentinel-primary text-ink-primary flex items-center gap-1.5"
            >
              <Play className="w-3.5 h-3.5 text-sentinel-primary" />
              <span>{t("studio.runSnippet")}</span>
            </button>
          )}

          <button
            type="button"
            onClick={() => setActiveTabId("special:repeater")}
            className="h-8 px-3 rounded border border-sentinel-warning/40 bg-sentinel-warning/15 text-sentinel-warning font-semibold flex items-center gap-1.5"
          >
            <Shield className="w-3.5 h-3.5" />
            <span>{t("studio.repeater")}</span>
          </button>
        </div>
      </div>

      {/* Main Split: Activity Rail + Side Drawer + Editor/Repeater */}
      <div className="flex-1 flex flex-col lg:flex-row min-h-0">
        {/* Compact Activity + Drawer Pane */}
        <div className="w-full lg:w-80 border-b lg:border-b-0 lg:border-e border-border-subtle bg-surface flex flex-col max-h-80 lg:max-h-none">
          <div className="p-1.5 border-b border-border-subtle grid grid-cols-5 gap-1 bg-inset">
            {(
              [
                { id: "explorer", icon: Files, labelKey: "studio.tabFiles" },
                { id: "skills", icon: Sparkles, labelKey: "studio.tabSkills" },
                { id: "burp", icon: Shield, labelKey: "studio.tabBurp" },
                { id: "sast", icon: ShieldAlert, labelKey: "studio.tabSast" },
                { id: "tools", icon: Wrench, labelKey: "studio.tabTools" },
              ] as const
            ).map((btn) => {
              const Icon = btn.icon;
              return (
                <button
                  key={btn.id}
                  type="button"
                  onClick={() => setActivityTab(btn.id)}
                  title={t(btn.labelKey)}
                  className={`py-1.5 px-1.5 rounded text-[11px] font-medium flex flex-col items-center justify-center gap-0.5 ${
                    activityTab === btn.id
                      ? "bg-elevated text-sentinel-primary border border-border-subtle"
                      : "text-ink-muted hover:text-ink-primary"
                  }`}
                >
                  <Icon className="w-3.5 h-3.5" />
                  <span className="truncate max-w-full">{t(btn.labelKey)}</span>
                </button>
              );
            })}
          </div>

          <div className="flex-1 overflow-y-auto p-2.5 space-y-2 text-xs">
            {activityTab === "explorer" && (
              <>
                <form onSubmit={handleCreateFile} className="flex gap-1">
                  <input
                    type="text"
                    dir="ltr"
                    value={newFilePath}
                    onChange={(e) => setNewFilePath(e.target.value)}
                    placeholder={t("studio.newFilePlaceholder")}
                    aria-label={t("studio.newFilePlaceholder")}
                    className="ltr-isolate flex-1 min-w-0 h-8 px-2 rounded bg-inset border border-border-subtle font-mono text-[11px]"
                  />
                  <button
                    type="submit"
                    aria-label={t("studio.createFile")}
                    className="h-8 px-2 rounded bg-elevated border border-border-subtle hover:border-sentinel-primary"
                  >
                    <Plus className="w-3.5 h-3.5" />
                  </button>
                </form>

                <input
                  type="search"
                  value={fileFilter}
                  onChange={(e) => setFileFilter(e.target.value)}
                  placeholder={t("studio.searchFiles")}
                  aria-label={t("studio.searchFiles")}
                  className="w-full h-8 px-2.5 rounded bg-inset border border-border-subtle text-xs"
                />

                <div className="space-y-0.5">
                  {fileFilter.trim() ? (
                    filteredFlatTree.map((item, idx) => (
                      <button
                        key={`${item.path}-${idx}`}
                        type="button"
                        onClick={() => void openFileTab(item.path)}
                        className={`w-full px-2 py-1 rounded text-start flex items-center gap-1.5 font-mono text-[11px] ltr-isolate truncate ${
                          activeTabId === item.path
                            ? "bg-sentinel-primary/15 text-sentinel-primary"
                            : "hover:bg-elevated text-ink-secondary"
                        }`}
                      >
                        <FileCode className="w-3.5 h-3.5 shrink-0 text-sentinel-primary" />
                        <span className="truncate">{item.path}</span>
                      </button>
                    ))
                  ) : (
                    renderTreeNodes(hierarchyTree)
                  )}
                </div>
              </>
            )}

            {activityTab === "skills" && (
              <>
                <input
                  type="search"
                  value={skillFilter}
                  onChange={(e) => setSkillFilter(e.target.value)}
                  placeholder={t("studio.searchSkills")}
                  aria-label={t("studio.searchSkills")}
                  className="w-full h-8 px-2.5 rounded bg-inset border border-border-subtle text-xs"
                />
                {filteredSkills.map((sk, idx) => (
                  <div key={`${sk.name || "skill"}-${idx}`} className="p-2 rounded bg-elevated border border-border-subtle space-y-1.5">
                    <div className="font-mono font-semibold text-sentinel-primary">{sk.name}</div>
                    <div className="text-[11px] text-ink-muted line-clamp-2">{sk.description}</div>
                    <div className="flex gap-1.5">
                      <button
                        type="button"
                        onClick={() => void openFileTab(`skills/${sk.name}/SKILL.md`, { isSkill: true, skillName: sk.name })}
                        className="px-2 py-0.5 rounded border border-border-subtle bg-inset text-[11px] hover:border-sentinel-primary"
                      >
                        {t("studio.openInEditor")}
                      </button>
                      <button
                        type="button"
                        onClick={() => void runSkillQuick(sk.name)}
                        className="px-2 py-0.5 rounded bg-sentinel-primary/15 text-sentinel-primary text-[11px] border border-sentinel-primary/35"
                      >
                        {t("studio.runSkill")}
                      </button>
                    </div>
                  </div>
                ))}
              </>
            )}

            {activityTab === "burp" && (
              <>
                <div className="p-2 rounded bg-elevated border border-border-subtle flex items-center justify-between">
                  <span className="font-mono">{t("burp.proxyPortLabel")} 8080</span>
                  <span className={burpProxyOnline ? "text-sentinel-success font-mono" : "text-sentinel-warning font-mono"}>
                    {burpProxyOnline ? t("states.online") : t("states.offline")}
                  </span>
                </div>
                {traffic.length === 0 ? (
                  <div className="py-4 text-center text-ink-muted">{t("studio.noTraffic")}</div>
                ) : (
                  traffic.map((tx, idx) => (
                    <button
                      key={`${tx.id || `${tx.method}-${tx.host}${tx.path}`}-${idx}`}
                      type="button"
                      onClick={() => {
                        const scheme = tx.scheme || "http";
                        const raw = `${tx.method} ${tx.path} HTTP/1.1\nHost: ${tx.host}\nUser-Agent: HunterAI-Studio/2.0\n\n`;
                        setRepRaw(raw);
                        setRepUrl(tx.url || `${scheme}://${tx.host}${tx.path}`);
                        setActiveTabId("special:repeater");
                      }}
                      className="w-full p-2 rounded bg-inset border border-border-subtle hover:border-sentinel-primary text-start font-mono text-[11px] ltr-isolate flex items-center justify-between gap-2"
                    >
                      <span className="text-sentinel-primary shrink-0">{tx.method}</span>
                      <span className="truncate flex-1">{tx.host}{tx.path}</span>
                      <span className="text-ink-muted">{tx.status || tx.response_status}</span>
                    </button>
                  ))
                )}
              </>
            )}

            {activityTab === "sast" && (
              <div className="space-y-2">
                <div className="font-semibold text-ink-primary">{t("studio.sastTitle")}</div>
                <p className="text-[11px] text-ink-muted">{t("studio.sastHint")}</p>
                <form onSubmit={runCodeIntelSast} className="space-y-2">
                  <textarea
                    rows={5}
                    dir="ltr"
                    value={sastCode}
                    onChange={(e) => setSastCode(e.target.value)}
                    placeholder={t("studio.sastCodePlaceholder")}
                    aria-label={t("studio.sastCodePlaceholder")}
                    className="ltr-isolate w-full p-2 rounded bg-inset border border-border-subtle font-mono text-[11px]"
                  />
                  <button
                    type="submit"
                    disabled={sastRunning}
                    className="w-full h-8 px-3 rounded bg-sentinel-primary text-sentinel-onAccent font-semibold flex items-center justify-center gap-1.5 disabled:opacity-50"
                  >
                    {sastRunning ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <ShieldAlert className="w-3.5 h-3.5" />}
                    <span>{t("studio.sastAuditBtn")}</span>
                  </button>
                </form>

                {sastResult && (
                  <div className="space-y-1.5 pt-1">
                    {sastResult.error && (
                      <div className="p-2 rounded bg-sentinel-danger/10 border border-sentinel-danger/40 text-sentinel-danger text-[11px]">
                        {sastResult.error}
                      </div>
                    )}
                    {sastResult.summary && (
                      <div className="p-2 rounded bg-elevated border border-border-subtle text-[11px] text-ink-primary">
                        {sastResult.summary}
                      </div>
                    )}
                    {sastFindings.length > 0 ? (
                      sastFindings.map((item, idx) => (
                        <div key={idx} className="p-2 rounded bg-inset border border-border-subtle space-y-0.5 text-[11px]">
                          <div className="font-mono font-semibold text-sentinel-warning">
                            {String(item.title || item.rule || item.type || "Finding")}
                          </div>
                          <div className="text-ink-secondary">
                            {String(item.message || item.description || JSON.stringify(item))}
                          </div>
                        </div>
                      ))
                    ) : !sastResult.error ? (
                      <pre dir="ltr" className="ltr-isolate p-2 rounded bg-inset border border-border-subtle font-mono text-[10px] max-h-40 overflow-auto">
                        {sanitizePlainTerminalText(JSON.stringify(sastResult, null, 2))}
                      </pre>
                    ) : null}
                  </div>
                )}
              </div>
            )}

            {activityTab === "tools" && (
              <div className="space-y-1">
                {tools.map((tl, idx) => (
                  <button
                    key={`${tl.name || "tool"}-${idx}`}
                    type="button"
                    onClick={() => setTermCmd(`${tl.name} --help`)}
                    className="w-full px-2 py-1.5 rounded bg-inset border border-border-subtle hover:border-sentinel-primary flex items-center justify-between font-mono text-[11px] ltr-isolate"
                  >
                    <span>{tl.name}</span>
                    <span className={tl.installed ? "text-sentinel-success" : "text-ink-muted"}>
                      {tl.installed ? t("states.ready") : t("states.missing")}
                    </span>
                  </button>
                ))}
              </div>
            )}
          </div>
        </div>

        {/* Center Workbench: Tabs + Monaco / Burp Repeater + Bottom Dock */}
        <div className="flex-1 flex flex-col min-w-0">
          {/* Tabs Strip */}
          <div className="px-2 py-1 border-b border-border-subtle bg-elevated/60 flex items-center gap-1 overflow-x-auto">
            {tabs.map((tb, idx) => {
              const active = tb.id === activeTabId;
              return (
                <div
                  key={`${tb.id}-${idx}`}
                  className={`flex items-center gap-1.5 px-2.5 py-1 rounded text-xs font-mono border shrink-0 ${
                    active
                      ? "bg-surface border-sentinel-primary text-ink-primary"
                      : "bg-inset border-border-subtle text-ink-muted"
                  }`}
                >
                  <button
                    type="button"
                    onClick={() => setActiveTabId(tb.id)}
                    className="ltr-isolate"
                  >
                    {tb.name}
                    {tb.dirty ? " *" : ""}
                  </button>
                  {!tb.isSpecial && (
                    <button
                      type="button"
                      onClick={() => closeTab(tb)}
                      aria-label={`${t("common.close")} ${tb.name}`}
                      className="text-ink-muted hover:text-sentinel-danger"
                    >
                      <X className="w-3 h-3" />
                    </button>
                  )}
                </div>
              );
            })}
          </div>

          {/* Editor Canvas */}
          <div className="flex-1 relative min-h-[340px]">
            <div
              ref={monacoContainerRef}
              dir="ltr"
              className={`w-full h-full min-h-[340px] ${activeTab?.isSpecial ? "hidden" : "block"}`}
            />

            {/* Embedded 2-Pane Burp Repeater */}
            {activeTab?.isSpecial && (
              <div className="p-4 space-y-3 h-full overflow-y-auto">
                <div className="flex flex-wrap items-center gap-2 text-xs">
                  <input
                    type="text"
                    dir="ltr"
                    value={repUrl}
                    onChange={(e) => setRepUrl(e.target.value)}
                    placeholder="https://target.example/api"
                    aria-label={t("common.target")}
                    className="ltr-isolate flex-1 min-w-[200px] h-9 px-3 rounded bg-inset border border-border-subtle font-mono"
                  />

                  <select
                    defaultValue=""
                    aria-label={t("burp.loadPreset")}
                    onChange={(e) => {
                      const p = REPEATER_PRESETS[e.target.value];
                      if (p) {
                        setRepUrl(p.url);
                        setRepRaw(p.raw);
                      }
                    }}
                    className="h-9 px-2.5 rounded bg-elevated border border-border-subtle font-mono"
                  >
                    <option value="">{t("burp.loadPreset")}...</option>
                    <option value="get">GET Probe</option>
                    <option value="post_json">POST JSON</option>
                    <option value="idor">IDOR Probe</option>
                  </select>

                  <label className="flex items-center gap-1.5 px-2.5 h-9 rounded bg-elevated border border-border-subtle cursor-pointer">
                    <input
                      type="checkbox"
                      checked={repUseProxy}
                      onChange={(e) => setRepUseProxy(e.target.checked)}
                    />
                    <span>{t("studio.routeViaBurp")}</span>
                  </label>

                  <button
                    type="button"
                    disabled={repSending}
                    onClick={() => void sendRepeater()}
                    className="min-h-[44px] sm:min-h-[36px] px-3.5 rounded bg-sentinel-primary text-sentinel-onAccent font-semibold flex items-center gap-1.5 disabled:opacity-50"
                  >
                    {repSending ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Send className="w-3.5 h-3.5 rtl:rotate-180" />}
                    <span>{t("studio.sendRequest")}</span>
                  </button>
                </div>

                <div className="grid grid-cols-1 xl:grid-cols-2 gap-3">
                  <div className="space-y-1.5">
                    <div className="text-xs font-semibold text-ink-secondary">{t("studio.rawRequest")}</div>
                    <textarea
                      rows={13}
                      dir="ltr"
                      value={repRaw}
                      onChange={(e) => setRepRaw(e.target.value)}
                      aria-label={t("studio.rawRequest")}
                      className="ltr-isolate w-full p-3 rounded-md bg-inset border border-border-subtle font-mono text-xs leading-relaxed"
                    />
                  </div>

                  <div className="space-y-1.5">
                    <div className="flex flex-wrap items-center justify-between gap-2 text-xs">
                      <div className="flex items-center gap-2">
                        <span className="font-semibold text-ink-secondary">{t("studio.httpResponse")}</span>
                        {repStatusMeta && (
                          <span className="font-mono text-[11px] px-2 py-0.5 rounded bg-elevated border border-border-subtle text-sentinel-primary ltr-isolate">
                            {repStatusMeta}
                          </span>
                        )}
                      </div>
                      <div className="flex items-center gap-1.5">
                        <button
                          type="button"
                          onClick={() => {
                            if (repResponse) {
                              void navigator.clipboard.writeText(repResponse);
                              setCopiedResp(true);
                              window.setTimeout(() => setCopiedResp(false), 1500);
                            }
                          }}
                          className="h-7 px-2 rounded border border-border-subtle bg-elevated text-ink-secondary flex items-center gap-1"
                        >
                          {copiedResp ? <Check className="w-3 h-3 text-sentinel-success" /> : <Copy className="w-3 h-3" />}
                          <span>{t("studio.copyResponse")}</span>
                        </button>
                        <button
                          type="button"
                          disabled={repAuditing || !repResponse}
                          onClick={() => void auditRepeater()}
                          className="h-7 px-2.5 rounded border border-sentinel-ai bg-sentinel-ai/15 text-sentinel-ai font-semibold flex items-center gap-1 disabled:opacity-40"
                        >
                          {repAuditing ? <Loader2 className="w-3 h-3 animate-spin" /> : <Sparkles className="w-3 h-3" />}
                          <span>{t("studio.aiAudit")}</span>
                        </button>
                      </div>
                    </div>

                    <textarea
                      rows={13}
                      readOnly
                      dir="ltr"
                      value={repResponse}
                      placeholder={t("studio.httpResponsePlaceholder")}
                      aria-label={t("studio.httpResponse")}
                      className="ltr-isolate w-full p-3 rounded-md bg-inset border border-border-subtle font-mono text-xs leading-relaxed text-ink-secondary"
                    />
                  </div>
                </div>

                {auditHtml && (
                  <div
                    className="sentinel-prose p-4 rounded-md bg-surface border border-sentinel-ai/40"
                    dangerouslySetInnerHTML={{ __html: auditHtml }}
                  />
                )}
              </div>
            )}
          </div>

          {/* Collapsible Bottom Terminal & Burp Sensor Dock */}
          <div className="border-t border-border-subtle bg-surface">
            <div className="px-3 py-1.5 flex flex-wrap items-center justify-between gap-2 bg-elevated/60 text-xs">
              <div className="flex items-center gap-1.5">
                <button
                  type="button"
                  aria-expanded={dockOpen}
                  onClick={() => setDockOpen((p) => !p)}
                  className="flex items-center gap-1 font-mono font-semibold text-ink-primary"
                >
                  {dockOpen ? <ChevronDown className="w-3.5 h-3.5" /> : <ChevronUp className="w-3.5 h-3.5" />}
                  <Terminal className="w-3.5 h-3.5 text-sentinel-primary" />
                  <span>{t("studio.dockTerm")}</span>
                </button>
                <button
                  type="button"
                  onClick={() => {
                    setDockTab("term");
                    setDockOpen(true);
                  }}
                  className={`px-2 py-0.5 rounded font-mono text-[11px] ${
                    dockTab === "term" ? "bg-surface text-sentinel-primary border border-border-subtle" : "text-ink-muted"
                  }`}
                >
                  {t("opencode.dockTerminal")}
                </button>
                <button
                  type="button"
                  onClick={() => {
                    setDockTab("burp");
                    setDockOpen(true);
                    void loadSidebarData();
                  }}
                  className={`px-2 py-0.5 rounded font-mono text-[11px] ${
                    dockTab === "burp" ? "bg-surface text-sentinel-warning border border-border-subtle" : "text-ink-muted"
                  }`}
                >
                  {t("studio.dockBurp")} ({sensoryEvents.length})
                </button>
              </div>
              <button
                type="button"
                onClick={() => void loadSidebarData()}
                className="text-ink-muted hover:text-ink-primary flex items-center gap-1"
              >
                <RefreshCw className="w-3 h-3" />
                <span>{t("common.refresh")}</span>
              </button>
            </div>

            {dockOpen && (
              <div className="p-2.5 space-y-2">
                {dockTab === "term" ? (
                  <>
                    <div
                      dir="ltr"
                      className="ltr-isolate h-28 overflow-y-auto rounded bg-inset border border-border-subtle p-2 font-mono text-[11px] text-ink-secondary whitespace-pre-wrap"
                    >
                      {dockLogs.join("\n")}
                    </div>
                    <form
                      onSubmit={(e) => {
                        e.preventDefault();
                        void runTerminal();
                      }}
                      className="flex gap-2"
                    >
                      <input
                        type="text"
                        dir="ltr"
                        value={termCmd}
                        onChange={(e) => setTermCmd(e.target.value)}
                        placeholder={t("opencode.terminalPlaceholder")}
                        aria-label={t("opencode.terminalPlaceholder")}
                        className="ltr-isolate flex-1 h-8 px-2.5 rounded bg-inset border border-border-subtle font-mono text-xs"
                      />
                      <button
                        type="submit"
                        className="h-8 px-3 rounded bg-sentinel-primary text-sentinel-onAccent text-xs font-semibold"
                      >
                        {t("studio.execute")}
                      </button>
                    </form>
                  </>
                ) : (
                  <pre dir="ltr" className="ltr-isolate h-36 overflow-y-auto rounded bg-inset border border-border-subtle p-2 font-mono text-[11px] text-ink-secondary">
                    {sanitizePlainTerminalText(JSON.stringify(sensoryEvents, null, 2))}
                  </pre>
                )}
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Unsaved Changes Confirmation Dialog */}
      {unsavedGuard.hasPendingPrompt && (
        <div
          className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/60 backdrop-blur-[1px]"
          onClick={unsavedGuard.cancelDiscard}
        >
          <div
            ref={discardModalTrapRef}
            role="dialog"
            aria-modal="true"
            aria-label={t("studio.unsavedTitle")}
            tabIndex={-1}
            onClick={(e) => e.stopPropagation()}
            className="w-full max-w-md bg-surface border border-border-strong rounded-xl shadow-sentinelMd p-4 space-y-3"
          >
            <div className="flex items-center gap-2 text-sentinel-warning">
              <AlertTriangle className="w-4 h-4 shrink-0" />
              <h3 className="text-sm font-semibold text-ink-primary">{t("studio.unsavedTitle")}</h3>
            </div>
            <p className="text-xs text-ink-secondary">{t("studio.unsavedWarning")}</p>
            <div className="flex items-center justify-end gap-2 pt-1">
              <button
                type="button"
                onClick={unsavedGuard.cancelDiscard}
                className="h-8 px-3 rounded border border-border-subtle bg-elevated text-xs text-ink-primary"
              >
                {t("common.cancel")}
              </button>
              <button
                type="button"
                onClick={unsavedGuard.confirmDiscard}
                className="h-8 px-3 rounded bg-sentinel-danger text-white text-xs font-semibold"
              >
                {t("studio.discardBtn")}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
