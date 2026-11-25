"use client";

import React, { useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  Bot,
  X,
  Plus,
  Trash2,
  Send,
  Paperclip,
  Maximize2,
  Minimize2,
  Loader2,
  ShieldAlert,
  Link2,
  Activity,
} from "lucide-react";
import { CopilotRef, usePlatform } from "@/lib/platform-context";
import { useI18n } from "@/lib/i18n";
import { renderSafeMarkdown } from "@/lib/sanitize";

interface ConversationSummary {
  conversation_id: string;
  title: string;
  engagement_id?: string | null;
  run_id?: string | null;
  mode: string;
  model: string;
  updated_at?: number;
}

interface ChatMessageItem {
  message_id: string;
  role: "user" | "assistant" | string;
  content: string;
  model?: string;
  mode?: string;
  refs?: CopilotRef[];
  metadata?: {
    provider?: string;
    fallback?: boolean;
    policy_outcome?: { allowed?: boolean; status?: string; reason?: string };
  };
  streaming?: boolean;
  approvalNotice?: {
    approval_id: string;
    action_type: string;
    tool_name: string;
    target: string;
    risk_tier: string;
  };
  policyNotice?: {
    status: string;
    reason: string;
  };
}

interface PendingAttachment {
  attachment_id: string;
  filename: string;
}

interface ModelChoice {
  id: string;
  label: string;
  kind?: string;
  provider?: string;
  model?: string;
  available?: boolean;
}

interface ModelsCatalogResponse {
  choices?: Array<{
    id?: string;
    kind?: string;
    provider?: string;
    model?: string;
    label?: string;
    available?: boolean;
  }>;
  local?: { available?: boolean; models?: string[] };
  cloud?: Array<{
    provider?: string;
    label?: string;
    default_model?: string;
    models?: string[];
  }>;
}

const COPILOT_MODES: Array<{ value: string; en: string; ar: string }> = [
  { value: "analyst", en: "analyst (Security Analyst)", ar: "analyst · محلل أمني" },
  { value: "redteam", en: "redteam (Operator)", ar: "redteam · مشغّل Red Team" },
  { value: "passive", en: "passive (Read-Only)", ar: "passive · تحليل سلبي" },
  { value: "recon", en: "recon (Recon & Surface)", ar: "recon · استطلاع وسطوح الهجوم" },
  { value: "triage", en: "triage (Findings Triage)", ar: "triage · فرز الأدلة والنتائج" },
];

export default function CopilotDrawer() {
  const {
    copilotOpen,
    setCopilotOpen,
    selectedEngagementId,
    runs,
    activeRunId,
    hunterHubHealth,
    hunterFetch,
    navigateToRef,
    refreshNow,
  } = usePlatform();
  const { t, lang, dir } = useI18n();

  const [drawerWidth, setDrawerWidth] = useState<number>(440);
  const [fullWidth, setFullWidth] = useState<boolean>(false);
  const [conversations, setConversations] = useState<ConversationSummary[]>([]);
  const [activeConvId, setActiveConvId] = useState<string>("");
  const [messages, setMessages] = useState<ChatMessageItem[]>([]);
  const [mode, setMode] = useState<string>("analyst");
  const [model, setModel] = useState<string>("auto");
  const [catalogModels, setCatalogModels] = useState<ModelChoice[]>([]);
  const [catalogLoaded, setCatalogLoaded] = useState<boolean>(false);
  const [prompt, setPrompt] = useState<string>("");
  const [attachments, setAttachments] = useState<PendingAttachment[]>([]);
  const [isStreaming, setIsStreaming] = useState<boolean>(false);
  const [uploadingFile, setUploadingFile] = useState<boolean>(false);
  const [statusNote, setStatusNote] = useState<string>("");

  const messagesEndRef = useRef<HTMLDivElement | null>(null);
  const streamAbortRef = useRef<AbortController | null>(null);
  const fileInputRef = useRef<HTMLInputElement | null>(null);

  const activeRunsCount = useMemo(
    () =>
      runs.filter((r) => ["running", "paused", "pending"].includes((r.status || "").toLowerCase()))
        .length,
    [runs]
  );

  const activeRun = useMemo(() => {
    const isRunActive = (r: { status?: string }) =>
      ["running", "paused", "pending"].includes((r.status || "").toLowerCase());
    if (activeRunId) {
      const ctxMatch = runs.find((r) => r.run_id === activeRunId && isRunActive(r));
      if (ctxMatch) return ctxMatch;
    }
    return runs.find(isRunActive) || null;
  }, [runs, activeRunId]);

  const loadModelsCatalog = useCallback(async () => {
    if (hunterHubHealth.status !== "connected") return;
    const autoLabel = lang === "ar" ? "auto · تلقائي (الموجه الذكي)" : "auto (Smart Router)";
    try {
      const res = await hunterFetch("/api/models/catalog");
      if (!res.ok) return;
      const cat = (await res.json()) as ModelsCatalogResponse;
      const list: ModelChoice[] = [{ id: "auto", label: autoLabel }];
      const seen = new Set<string>(["auto"]);

      if (Array.isArray(cat.choices) && cat.choices.length > 0) {
        for (const ch of cat.choices) {
          if (!ch?.id || ch.available === false || seen.has(ch.id)) continue;
          seen.add(ch.id);
          list.push({
            id: ch.id,
            label: ch.label || `${ch.kind === "local" ? "Local" : "Cloud"} · ${ch.model || ch.id}`,
            kind: ch.kind,
            provider: ch.provider,
            model: ch.model,
            available: ch.available,
          });
        }
      } else {
        for (const c of cat.cloud || []) {
          if (!c?.provider) continue;
          const models =
            Array.isArray(c.models) && c.models.length > 0
              ? c.models
              : c.default_model
                ? [c.default_model]
                : [];
          for (const m of models) {
            if (!m) continue;
            const id = `api:${c.provider}:${m}`;
            if (seen.has(id)) continue;
            seen.add(id);
            list.push({
              id,
              label: `${c.label || c.provider} · ${m}`,
              kind: "cloud",
              provider: c.provider,
              model: m,
              available: true,
            });
          }
        }
        for (const m of cat.local?.models || []) {
          if (!m) continue;
          const id = `local:${m}`;
          if (seen.has(id)) continue;
          seen.add(id);
          list.push({
            id,
            label: `Ollama · ${m}`,
            kind: "local",
            provider: "ollama",
            model: m,
            available: true,
          });
        }
      }

      setCatalogModels(list);
      setCatalogLoaded(true);
    } catch {
      // Fall back gracefully to configured providers reported by Hub health
    }
  }, [hunterHubHealth.status, hunterFetch, lang]);

  const modelOptions = useMemo<ModelChoice[]>(() => {
    const autoLabel = lang === "ar" ? "auto · تلقائي (الموجه الذكي)" : "auto (Smart Router)";
    const list: ModelChoice[] = [];
    const seen = new Set<string>();
    const pushUnique = (opt: ModelChoice) => {
      if (!opt.id || seen.has(opt.id)) return;
      seen.add(opt.id);
      list.push(opt);
    };

    if (catalogLoaded && catalogModels.length > 0) {
      for (const item of catalogModels) {
        pushUnique(item);
      }
    } else {
      pushUnique({ id: "auto", label: autoLabel });
      const cloudProviders = hunterHubHealth.services?.cloud_providers || [];
      for (const prov of cloudProviders) {
        if (!prov) continue;
        pushUnique({
          id: `api:${prov}`,
          label: `Cloud · ${prov}`,
          kind: "cloud",
          provider: prov,
          available: true,
        });
      }
      if (hunterHubHealth.services?.lm_studio?.online) {
        pushUnique({
          id: "lmstudio:local-model",
          label: "LM Studio · local-model",
          kind: "local",
          provider: "lm_studio",
          available: true,
        });
      }
    }

    if (model && !seen.has(model)) {
      pushUnique({ id: model, label: model });
    }
    return list;
  }, [catalogLoaded, catalogModels, hunterHubHealth.services, lang, model]);

  const modeOptions = useMemo(() => {
    const opts = [...COPILOT_MODES];
    if (mode && !opts.some((m) => m.value === mode)) {
      opts.push({ value: mode, en: mode, ar: mode });
    }
    return opts;
  }, [mode]);

  const persistConversationPatch = useCallback(
    async (cid: string, patch: { mode?: string; model?: string }) => {
      if (!cid) return;
      try {
        const res = await hunterFetch(`/api/copilot/conversations/${encodeURIComponent(cid)}`, {
          method: "PATCH",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(patch),
        });
        if (!res.ok) return;
        const data = (await res.json().catch(() => null)) as {
          conversation?: ConversationSummary;
        } | null;
        if (data?.conversation) {
          setConversations((prev) =>
            prev.map((c) => (c.conversation_id === cid ? data.conversation! : c))
          );
        }
      } catch {
        // Non-fatal; active selections are still passed in chat requests
      }
    },
    [hunterFetch]
  );

  const handleModeChange = (nextMode: string) => {
    setMode(nextMode);
    if (activeConvId) {
      setConversations((prev) =>
        prev.map((c) => (c.conversation_id === activeConvId ? { ...c, mode: nextMode } : c))
      );
      void persistConversationPatch(activeConvId, { mode: nextMode });
    }
  };

  const handleModelChange = (nextModel: string) => {
    setModel(nextModel);
    if (activeConvId) {
      setConversations((prev) =>
        prev.map((c) => (c.conversation_id === activeConvId ? { ...c, model: nextModel } : c))
      );
      void persistConversationPatch(activeConvId, { model: nextModel });
    }
  };

  const loadConversations = useCallback(async () => {
    if (hunterHubHealth.status !== "connected") return;
    try {
      const res = await hunterFetch("/api/copilot/conversations?limit=50");
      if (!res.ok) return;
      const data = (await res.json()) as { conversations?: ConversationSummary[] };
      const list = Array.isArray(data.conversations) ? data.conversations : [];
      setConversations(list);
      if (!activeConvId && list.length > 0) {
        setActiveConvId(list[0].conversation_id);
      }
    } catch {
      // Hub unavailable
    }
  }, [hunterHubHealth.status, hunterFetch, activeConvId]);

  const loadConversationMessages = useCallback(
    async (cid: string) => {
      if (!cid || hunterHubHealth.status !== "connected") return;
      try {
        const res = await hunterFetch(`/api/copilot/conversations/${encodeURIComponent(cid)}`);
        if (!res.ok) return;
        const data = (await res.json()) as {
          conversation?: ConversationSummary;
          messages?: ChatMessageItem[];
        };
        if (data.conversation) {
          setMode(data.conversation.mode || "analyst");
          setModel(data.conversation.model || "auto");
        }
        setMessages(Array.isArray(data.messages) ? data.messages : []);
      } catch {
        // Ignore load error
      }
    },
    [hunterHubHealth.status, hunterFetch]
  );

  useEffect(() => {
    if (copilotOpen && hunterHubHealth.status === "connected") {
      void loadConversations();
      void loadModelsCatalog();
    }
  }, [copilotOpen, hunterHubHealth.status, loadConversations, loadModelsCatalog]);

  useEffect(() => {
    if (copilotOpen && activeConvId && !isStreaming) {
      void loadConversationMessages(activeConvId);
    }
  }, [copilotOpen, activeConvId, isStreaming, loadConversationMessages]);

  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [messages]);

  useEffect(() => {
    if (!copilotOpen) return;
    const onKeyDown = (ev: KeyboardEvent) => {
      if (ev.key === "Escape") {
        setCopilotOpen(false);
      }
    };
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, [copilotOpen, setCopilotOpen]);

  const handlePointerResize = (e: React.PointerEvent<HTMLDivElement>) => {
    if (fullWidth) return;
    e.preventDefault();
    const startX = e.clientX;
    const startW = drawerWidth;
    const sign = dir === "rtl" ? 1 : -1;

    const onMove = (moveEv: PointerEvent) => {
      const delta = (moveEv.clientX - startX) * sign;
      const next = Math.min(760, Math.max(340, startW + delta));
      setDrawerWidth(next);
    };
    const onUp = () => {
      window.removeEventListener("pointermove", onMove);
      window.removeEventListener("pointerup", onUp);
    };
    window.addEventListener("pointermove", onMove);
    window.addEventListener("pointerup", onUp);
  };

  const handleResizeKeyDown = (e: React.KeyboardEvent<HTMLDivElement>) => {
    if (fullWidth) return;
    const step = 24;
    if (e.key === "ArrowLeft") {
      e.preventDefault();
      setDrawerWidth((w) => Math.min(760, Math.max(340, w + (dir === "rtl" ? -step : step))));
    } else if (e.key === "ArrowRight") {
      e.preventDefault();
      setDrawerWidth((w) => Math.min(760, Math.max(340, w + (dir === "rtl" ? step : -step))));
    }
  };

  const handleNewConversation = async () => {
    setStatusNote("");
    try {
      const res = await hunterFetch("/api/copilot/conversations", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          title: "New Investigation",
          engagement_id: selectedEngagementId || null,
          run_id: activeRun?.run_id || null,
          mode,
          model,
          set_active: true,
        }),
      });
      if (!res.ok) return;
      const data = (await res.json()) as { conversation?: ConversationSummary };
      if (data.conversation) {
        setConversations((prev) => [data.conversation!, ...prev]);
        setActiveConvId(data.conversation.conversation_id);
        setMessages([]);
      }
    } catch {
      setStatusNote(t("copilot.offlineBanner"));
    }
  };

  const handleDeleteConversation = async () => {
    if (!activeConvId) return;
    try {
      const res = await hunterFetch(`/api/copilot/conversations/${encodeURIComponent(activeConvId)}`, {
        method: "DELETE",
      });
      if (!res.ok) return;
      const remaining = conversations.filter((c) => c.conversation_id !== activeConvId);
      setConversations(remaining);
      setActiveConvId(remaining[0]?.conversation_id || "");
      setMessages([]);
    } catch {
      setStatusNote(t("copilot.offlineBanner"));
    }
  };

  const handleFileUpload = async (ev: React.ChangeEvent<HTMLInputElement>) => {
    const file = ev.target.files?.[0];
    if (!file) return;
    setUploadingFile(true);
    setStatusNote("");
    try {
      const fd = new FormData();
      fd.append("file", file);
      if (activeConvId) {
        fd.append("conversation_id", activeConvId);
      }
      const res = await hunterFetch("/api/copilot/attachments", {
        method: "POST",
        body: fd,
      });
      if (!res.ok) {
        const err = (await res.json().catch(() => null)) as { detail?: string } | null;
        setStatusNote(err?.detail || `Upload failed (${res.status})`);
      } else {
        const data = (await res.json()) as { attachment?: PendingAttachment };
        if (data.attachment) {
          setAttachments((prev) => [...prev, data.attachment!]);
        }
      }
    } catch {
      setStatusNote(t("copilot.offlineBanner"));
    } finally {
      setUploadingFile(false);
      if (fileInputRef.current) fileInputRef.current.value = "";
    }
  };

  const handleSend = async (ev?: React.FormEvent) => {
    if (ev) ev.preventDefault();
    const text = prompt.trim();
    if (!text || isStreaming) return;

    setStatusNote("");
    setPrompt("");
    const attachmentIds = attachments.map((a) => a.attachment_id);
    setAttachments([]);

    const tempUserMsg: ChatMessageItem = {
      message_id: `tmp-u-${Date.now()}`,
      role: "user",
      content: text,
    };
    const tempAssistId = `tmp-a-${Date.now()}`;
    const tempAssistMsg: ChatMessageItem = {
      message_id: tempAssistId,
      role: "assistant",
      content: "",
      streaming: true,
      refs: [],
    };

    setMessages((prev) => [...prev, tempUserMsg, tempAssistMsg]);
    setIsStreaming(true);

    if (streamAbortRef.current) {
      streamAbortRef.current.abort();
    }
    const controller = new AbortController();
    streamAbortRef.current = controller;

    try {
      const activeConv = conversations.find((c) => c.conversation_id === activeConvId);
      const effectiveRunId = activeRun?.run_id || activeConv?.run_id || null;
      const bodyPayload: Record<string, unknown> = {
        message: text,
        conversation_id: activeConvId || null,
        engagement_id: selectedEngagementId || null,
        mode,
        model,
        attachment_ids: attachmentIds,
      };
      if (effectiveRunId) {
        bodyPayload.run_id = effectiveRunId;
      }

      const res = await hunterFetch("/api/copilot/chat/stream", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Accept: "text/event-stream",
        },
        body: JSON.stringify(bodyPayload),
        signal: controller.signal,
      });

      if (!res.ok || !res.body) {
        throw new Error(`HTTP ${res.status}`);
      }

      const reader = res.body.getReader();
      const decoder = new TextDecoder("utf-8");
      let buffer = "";
      let streamConvId = activeConvId;

      const processBlock = (block: string) => {
        const lines = block.split(/\r?\n/);
        let eventName = "message";
        const dataLines: string[] = [];
        for (const line of lines) {
          if (!line || line.startsWith(":")) continue;
          if (line.startsWith("event:")) {
            eventName = line.slice(6).trim() || "message";
          } else if (line.startsWith("data:")) {
            dataLines.push(line.slice(5).trimStart());
          }
        }
        if (dataLines.length === 0) return;

        let payload: Record<string, unknown>;
        try {
          payload = JSON.parse(dataLines.join("\n")) as Record<string, unknown>;
        } catch {
          return;
        }

        if (typeof payload.conversation_id === "string" && payload.conversation_id) {
          streamConvId = payload.conversation_id;
          setActiveConvId(payload.conversation_id);
        }

        if (eventName === "context" || eventName === "refs") {
          const refs = Array.isArray(payload.refs) ? (payload.refs as CopilotRef[]) : [];
          setMessages((prev) =>
            prev.map((m) => (m.message_id === tempAssistId ? { ...m, refs } : m))
          );
        } else if (eventName === "approval_request") {
          const ap = payload.approval as ChatMessageItem["approvalNotice"] | undefined;
          if (ap) {
            setMessages((prev) =>
              prev.map((m) => (m.message_id === tempAssistId ? { ...m, approvalNotice: ap } : m))
            );
            void refreshNow();
          }
        } else if (eventName === "policy_blocked") {
          const pol = payload.policy as ChatMessageItem["policyNotice"] | undefined;
          if (pol) {
            setMessages((prev) =>
              prev.map((m) => (m.message_id === tempAssistId ? { ...m, policyNotice: pol } : m))
            );
          }
        } else if (eventName === "token") {
          const delta = typeof payload.delta === "string" ? payload.delta : "";
          const isFallback = Boolean(payload.fallback);
          setMessages((prev) =>
            prev.map((m) =>
              m.message_id === tempAssistId
                ? {
                    ...m,
                    content: m.content + delta,
                    metadata: isFallback ? { ...m.metadata, fallback: true } : m.metadata,
                  }
                : m
            )
          );
        } else if (eventName === "done") {
          const answer = typeof payload.answer === "string" ? payload.answer : "";
          const refs = Array.isArray(payload.refs) ? (payload.refs as CopilotRef[]) : [];
          const provider = typeof payload.provider === "string" ? payload.provider : "";
          const modelUsed = typeof payload.model_used === "string" ? payload.model_used : "";
          const fallback = Boolean(payload.fallback);
          setMessages((prev) =>
            prev.map((m) =>
              m.message_id === tempAssistId
                ? {
                    ...m,
                    content: answer || m.content,
                    model: modelUsed || m.model,
                    refs,
                    streaming: false,
                    metadata: { ...m.metadata, provider, fallback },
                  }
                : m
            )
          );
          void loadConversations();
        } else if (eventName === "error") {
          const errText = typeof payload.error === "string" ? payload.error : "Stream error";
          setMessages((prev) =>
            prev.map((m) =>
              m.message_id === tempAssistId
                ? { ...m, content: `Error: ${errText}`, streaming: false }
                : m
            )
          );
        }
      };

      const flushCompleteBlocks = () => {
        let idx: number;
        while ((idx = buffer.search(/\r?\n\r?\n/)) !== -1) {
          const sepLen = buffer.slice(idx).startsWith("\r\n\r\n") ? 4 : 2;
          const block = buffer.slice(0, idx);
          buffer = buffer.slice(idx + sepLen);
          processBlock(block);
        }
      };

      while (true) {
        const { value, done } = await reader.read();
        if (done) {
          buffer += decoder.decode();
          break;
        }
        buffer += decoder.decode(value, { stream: true });
        flushCompleteBlocks();
      }

      // Flush any trailing blocks / frame remaining at EOF without \n\n
      flushCompleteBlocks();
      if (buffer.trim()) {
        processBlock(buffer);
        buffer = "";
      }

      setMessages((prev) =>
        prev.map((m) =>
          m.message_id === tempAssistId && m.streaming ? { ...m, streaming: false } : m
        )
      );

      if (streamConvId && !conversations.some((c) => c.conversation_id === streamConvId)) {
        void loadConversations();
      }
    } catch (err) {
      if (!controller.signal.aborted) {
        const msg = err instanceof Error ? err.message : t("copilot.offlineBanner");
        setMessages((prev) =>
          prev.map((m) =>
            m.message_id === tempAssistId
              ? { ...m, content: msg, streaming: false }
              : m
          )
        );
      }
    } finally {
      setIsStreaming(false);
    }
  };

  const handleRefClick = (ref: CopilotRef) => {
    const handled = navigateToRef(ref);
    if (!handled) {
      setStatusNote(`${t("copilot.refMissing")} (${ref.kind}: ${ref.id})`);
    } else {
      setStatusNote("");
    }
  };

  if (!copilotOpen) {
    return null;
  }

  return (
    <aside
      role="dialog"
      aria-modal="false"
      aria-labelledby="copilot-drawer-title"
      style={fullWidth ? { width: "100vw" } : { width: `min(100vw, ${drawerWidth}px)` }}
      className="fixed inset-y-0 end-0 z-50 bg-surface border-s border-border-strong shadow-sentinelMd flex flex-col"
    >
      {/* Drag & Keyboard Resize Handle */}
      {!fullWidth && (
        <div
          role="separator"
          aria-orientation="vertical"
          aria-label="Resize Copilot drawer"
          tabIndex={0}
          onPointerDown={handlePointerResize}
          onKeyDown={handleResizeKeyDown}
          className="hidden sm:block absolute inset-y-0 start-0 w-1.5 cursor-col-resize hover:bg-sentinel-primary/40 transition-colors"
        />
      )}

      {/* Header */}
      <div className="px-4 py-3 border-b border-border-subtle flex items-center justify-between gap-2">
        <div className="flex items-center gap-2 min-w-0">
          <Bot className="w-5 h-5 text-sentinel-ai shrink-0" />
          <div className="min-w-0">
            <h2 id="copilot-drawer-title" className="text-sm font-semibold text-ink-primary truncate">
              {t("copilot.title")}
            </h2>
            <div className="flex items-center gap-2 text-[11px] font-mono text-ink-muted">
              <span
                className={
                  hunterHubHealth.status === "connected"
                    ? "text-sentinel-success"
                    : "text-sentinel-danger"
                }
              >
                {hunterHubHealth.status === "connected"
                  ? t("status.connected")
                  : t("status.offline")}
              </span>
              {activeRunsCount > 0 && (
                <span className="flex items-center gap-1 text-sentinel-primary tabular-nums">
                  <Activity className="w-3 h-3" />
                  {activeRunsCount} active
                </span>
              )}
            </div>
          </div>
        </div>

        <div className="flex items-center gap-1">
          <button
            type="button"
            onClick={() => setFullWidth((prev) => !prev)}
            aria-label={fullWidth ? t("copilot.restoreWidth") : t("copilot.expandWidth")}
            title={fullWidth ? t("copilot.restoreWidth") : t("copilot.expandWidth")}
            className="h-8 w-8 rounded border border-border-subtle bg-elevated text-ink-secondary hover:text-ink-primary flex items-center justify-center"
          >
            {fullWidth ? <Minimize2 className="w-4 h-4" /> : <Maximize2 className="w-4 h-4" />}
          </button>

          <button
            type="button"
            onClick={() => setCopilotOpen(false)}
            aria-label={t("common.close")}
            className="h-8 w-8 rounded border border-border-subtle bg-elevated text-ink-secondary hover:text-ink-primary flex items-center justify-center"
          >
            <X className="w-4 h-4" />
          </button>
        </div>
      </div>

      {/* Session & Mode Controls */}
      <div className="px-4 py-2.5 border-b border-border-subtle bg-elevated/60 space-y-2">
        <div className="flex items-center gap-1.5">
          <select
            value={activeConvId}
            onChange={(e) => setActiveConvId(e.target.value)}
            aria-label="Copilot conversation"
            className="flex-1 min-w-0 h-8 px-2 rounded bg-inset border border-border-subtle text-xs text-ink-primary truncate"
          >
            {conversations.length === 0 && <option value="">{t("copilot.newSession")}</option>}
            {conversations.map((c) => (
              <option key={c.conversation_id} value={c.conversation_id}>
                {c.title || c.conversation_id}
              </option>
            ))}
          </select>

          <button
            type="button"
            onClick={() => void handleNewConversation()}
            title={t("copilot.newSession")}
            aria-label={t("copilot.newSession")}
            className="h-8 px-2.5 rounded border border-border-subtle bg-elevated hover:border-border-strong text-xs text-ink-primary flex items-center gap-1 shrink-0"
          >
            <Plus className="w-3.5 h-3.5 text-sentinel-primary" />
          </button>

          <button
            type="button"
            disabled={!activeConvId}
            onClick={() => void handleDeleteConversation()}
            title={t("copilot.deleteSession")}
            aria-label={t("copilot.deleteSession")}
            className="h-8 px-2.5 rounded border border-border-subtle bg-elevated hover:border-border-strong text-xs text-ink-muted hover:text-sentinel-danger disabled:opacity-40 shrink-0"
          >
            <Trash2 className="w-3.5 h-3.5" />
          </button>
        </div>

        <div className="flex items-center gap-2 text-xs">
          <label className="flex items-center gap-1.5 flex-1 min-w-0">
            <span className="text-ink-muted shrink-0">{t("copilot.modeLabel")}:</span>
            <select
              value={mode}
              onChange={(e) => handleModeChange(e.target.value)}
              className="w-full min-w-0 h-7 px-2 rounded bg-inset border border-border-subtle text-xs text-ink-primary truncate"
            >
              {modeOptions.map((opt) => (
                <option key={opt.value} value={opt.value}>
                  {lang === "ar" ? opt.ar : opt.en}
                </option>
              ))}
            </select>
          </label>

          <label className="flex items-center gap-1.5 flex-1 min-w-0">
            <span className="text-ink-muted shrink-0">{t("copilot.modelLabel")}:</span>
            <select
              value={model}
              onChange={(e) => handleModelChange(e.target.value)}
              className="w-full min-w-0 h-7 px-2 rounded bg-inset border border-border-subtle text-xs font-mono text-ink-primary ltr-isolate truncate"
            >
              {modelOptions.map((opt) => (
                <option key={opt.id} value={opt.id}>
                  {opt.label}
                </option>
              ))}
            </select>
          </label>
        </div>
      </div>

      {/* Offline / Status Banner */}
      {(hunterHubHealth.status === "offline" || statusNote) && (
        <div
          role="status"
          className="mx-4 mt-3 px-3 py-2 rounded-md border border-[var(--accent-warning)]/40 bg-[var(--accent-warning-bg)] text-sentinel-warning text-xs"
        >
          {hunterHubHealth.status === "offline" ? t("copilot.offlineBanner") : statusNote}
        </div>
      )}

      {/* Messages */}
      <div className="flex-1 overflow-y-auto p-4 space-y-3">
        {messages.length === 0 ? (
          <div className="h-full flex flex-col items-center justify-center text-center px-4 text-ink-muted space-y-2">
            <Bot className="w-10 h-10 text-sentinel-ai opacity-50" />
            <p className="text-xs leading-relaxed max-w-xs">{t("copilot.noConversations")}</p>
          </div>
        ) : (
          messages.map((msg) => {
            const isUser = msg.role === "user";
            const safeHtml = !isUser && msg.content ? renderSafeMarkdown(msg.content) : "";
            return (
              <div
                key={msg.message_id}
                className={`rounded-lg border p-3 space-y-2 ${
                  isUser
                    ? "bg-elevated border-border-strong ms-6"
                    : "bg-inset border-border-subtle me-4"
                }`}
              >
                <div className="flex items-center justify-between gap-2 text-[11px] font-mono text-ink-muted">
                  <span className={isUser ? "text-sentinel-primary font-semibold" : "text-sentinel-ai font-semibold"}>
                    {isUser ? "OPERATOR" : "COPILOT"}
                  </span>
                  <div className="flex items-center gap-1.5">
                    {msg.metadata?.fallback && (
                      <span className="px-1.5 py-0.5 rounded bg-[var(--accent-warning-bg)] text-sentinel-warning border border-[var(--accent-warning)]/30">
                        {t("copilot.fallbackTag")}
                      </span>
                    )}
                    {msg.model && <span className="ltr-isolate">{msg.model}</span>}
                  </div>
                </div>

                {msg.policyNotice && (
                  <div className="p-2 rounded border border-[var(--accent-danger)]/40 bg-[var(--accent-danger-bg)] text-sentinel-danger text-xs flex items-start gap-1.5">
                    <ShieldAlert className="w-4 h-4 shrink-0 mt-0.5" />
                    <div>
                      <div className="font-semibold">{t("copilot.policyBlocked")}</div>
                      <div>{msg.policyNotice.reason}</div>
                    </div>
                  </div>
                )}

                {msg.approvalNotice && (
                  <button
                    type="button"
                    onClick={() =>
                      handleRefClick({
                        kind: "approval",
                        id: msg.approvalNotice!.approval_id,
                      })
                    }
                    className="w-full text-start p-2 rounded border border-[var(--accent-warning)]/40 bg-[var(--accent-warning-bg)] text-sentinel-warning text-xs space-y-0.5"
                  >
                    <div className="font-semibold">{t("copilot.approvalQueued")}</div>
                    <div className="font-mono ltr-isolate">
                      {msg.approvalNotice.action_type} · {msg.approvalNotice.tool_name} ·{" "}
                      {msg.approvalNotice.target}
                    </div>
                  </button>
                )}

                {isUser ? (
                  <p className="text-sm text-ink-primary whitespace-pre-wrap">{msg.content}</p>
                ) : msg.streaming && !msg.content ? (
                  <div className="flex items-center gap-2 text-xs text-ink-muted">
                    <Loader2 className="w-3.5 h-3.5 animate-spin text-sentinel-ai" />
                    <span>{t("copilot.sending")}</span>
                  </div>
                ) : (
                  <div
                    className="sentinel-prose"
                    dangerouslySetInnerHTML={{ __html: safeHtml }}
                  />
                )}

                {Array.isArray(msg.refs) && msg.refs.length > 0 && (
                  <div className="pt-2 border-t border-border-subtle space-y-1">
                    <div className="text-[10px] font-mono uppercase text-ink-muted">
                      {t("copilot.refsTitle")}
                    </div>
                    <div className="flex flex-wrap gap-1.5">
                      {msg.refs.slice(0, 8).map((ref) => (
                        <button
                          key={`${ref.kind}:${ref.id}`}
                          type="button"
                          onClick={() => handleRefClick(ref)}
                          className="inline-flex items-center gap-1 px-2 py-0.5 rounded bg-elevated border border-border-subtle hover:border-sentinel-primary text-[11px] font-mono text-sentinel-primary ltr-isolate"
                        >
                          <Link2 className="w-3 h-3 shrink-0" />
                          <span className="truncate max-w-[200px]">
                            {ref.label || `${ref.kind}:${ref.id}`}
                          </span>
                        </button>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            );
          })
        )}
        <div ref={messagesEndRef} />
      </div>

      {/* Composer */}
      <form onSubmit={handleSend} className="p-3 border-t border-border-subtle bg-surface space-y-2">
        {attachments.length > 0 && (
          <div className="flex flex-wrap gap-1.5">
            {attachments.map((att) => (
              <span
                key={att.attachment_id}
                className="inline-flex items-center gap-1 px-2 py-0.5 rounded bg-elevated border border-border-subtle text-xs font-mono text-ink-secondary ltr-isolate"
              >
                <span>{att.filename}</span>
                <button
                  type="button"
                  onClick={() =>
                    setAttachments((prev) =>
                      prev.filter((item) => item.attachment_id !== att.attachment_id)
                    )
                  }
                  aria-label={`Remove ${att.filename}`}
                  className="text-ink-muted hover:text-sentinel-danger"
                >
                  <X className="w-3 h-3" />
                </button>
              </span>
            ))}
          </div>
        )}

        <div className="flex items-end gap-2">
          <input
            ref={fileInputRef}
            type="file"
            className="hidden"
            onChange={(e) => void handleFileUpload(e)}
          />
          <button
            type="button"
            disabled={uploadingFile || hunterHubHealth.status === "offline"}
            onClick={() => fileInputRef.current?.click()}
            title={t("copilot.attachBtn")}
            aria-label={t("copilot.attachBtn")}
            className="h-9 w-9 rounded-md border border-border-subtle bg-elevated hover:border-border-strong text-ink-secondary hover:text-ink-primary flex items-center justify-center shrink-0 disabled:opacity-40"
          >
            {uploadingFile ? (
              <Loader2 className="w-4 h-4 animate-spin" />
            ) : (
              <Paperclip className="w-4 h-4" />
            )}
          </button>

          <textarea
            rows={2}
            value={prompt}
            onChange={(e) => setPrompt(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === "Enter" && !e.shiftKey) {
                e.preventDefault();
                void handleSend();
              }
            }}
            placeholder={t("copilot.placeholder")}
            aria-label={t("copilot.placeholder")}
            className="flex-1 px-3 py-2 rounded-md bg-inset border border-border-subtle text-xs text-ink-primary placeholder:text-ink-muted resize-none focus:border-sentinel-primary"
          />

          <button
            type="submit"
            disabled={isStreaming || !prompt.trim() || hunterHubHealth.status === "offline"}
            aria-label={t("copilot.sendBtn")}
            className="h-9 px-3.5 rounded-md bg-sentinel-primary text-sentinel-onAccent text-xs font-semibold flex items-center gap-1.5 hover:opacity-90 disabled:opacity-40 shrink-0"
          >
            {isStreaming ? (
              <Loader2 className="w-4 h-4 animate-spin" />
            ) : (
              <Send className="w-4 h-4" />
            )}
          </button>
        </div>
      </form>
    </aside>
  );
}
