"use client";

import React, { useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  Bot,
  X,
  Plus,
  Trash2,
  Send,
  Square,
  Paperclip,
  Maximize2,
  Minimize2,
  Loader2,
  ShieldAlert,
  Link2,
  Activity,
  Play,
  Pause,
  RotateCcw,
  Lock,
  ChevronRight,
  ChevronDown,
  ArrowDown,
  Check,
  XCircle,
  BookOpen,
  Sparkles,
  Wrench,
  Cpu,
} from "lucide-react";
import {
  ApprovalExecutionResult,
  ApprovalItem,
  CopilotCitation,
  CopilotRef,
  MissionRun,
  ModelCatalogResponse,
  ModelChoiceItem,
  normalizeRunProgressPercent,
} from "@/lib/api-types";
import { usePlatform } from "@/lib/platform-context";
import { useI18n } from "@/lib/i18n";
import { renderSafeMarkdown } from "@/lib/sanitize";
import { useAutoScroll } from "@/hooks/use-auto-scroll";
import { sanitizePlainTerminalText } from "@/lib/terminal-sanitizer";

interface ConversationSummary {
  conversation_id: string;
  title: string;
  engagement_id?: string | null;
  run_id?: string | null;
  mode: string;
  model: string;
  updated_at?: number;
}

interface ApprovalNoticeData {
  approval_id: string;
  action_type: string;
  tool_name: string;
  target: string;
  command_args?: string;
  risk_tier: string;
  proposal_digest?: string;
  rationale?: string;
  status?: string;
  decision_note?: string;
  execution?: ApprovalExecutionResult | null;
}

interface ChatMessageItem {
  id: string;
  message_id: string;
  role: "user" | "assistant" | string;
  content: string;
  thinking?: string;
  model?: string;
  mode?: string;
  approval_id?: string | null;
  refs?: CopilotRef[];
  citations?: CopilotCitation[];
  metadata?: {
    provider?: string;
    fallback?: boolean;
    aborted?: boolean;
    policy_outcome?: { allowed?: boolean; status?: string; reason?: string };
  };
  streaming?: boolean;
  approvalNotice?: ApprovalNoticeData;
  approval?: ApprovalNoticeData | null;
  policyNotice?: {
    allowed?: boolean;
    status: string;
    reason: string;
  };
}

interface PendingAttachment {
  attachment_id: string;
  filename: string;
}

function getMessageApprovalId(msg: Partial<ChatMessageItem> | undefined): string {
  if (!msg) return "";
  return (
    msg.approvalNotice?.approval_id ||
    msg.approval?.approval_id ||
    (typeof msg.approval_id === "string" ? msg.approval_id : "")
  );
}

function derivePolicyNotice(
  raw: Partial<ChatMessageItem>,
  existing?: ChatMessageItem
): ChatMessageItem["policyNotice"] | undefined {
  if (raw.policyNotice && (raw.policyNotice.reason || raw.policyNotice.status)) {
    return raw.policyNotice;
  }
  const outcome = raw.metadata?.policy_outcome;
  if (outcome && outcome.allowed === false && (outcome.reason || outcome.status)) {
    return {
      allowed: false,
      status: String(outcome.status || "BLOCKED"),
      reason: String(outcome.reason || "Blocked by PolicyEngine"),
    };
  }
  return existing?.policyNotice;
}

function normalizeServerMessage(raw: Partial<ChatMessageItem>, idx: number): ChatMessageItem {
  const mid = String(raw.message_id || raw.id || `msg-${idx}`);
  return {
    ...raw,
    id: mid,
    message_id: mid,
    role: String(raw.role || "assistant"),
    content: String(raw.content || ""),
    thinking: typeof raw.thinking === "string" ? raw.thinking : undefined,
    refs: Array.isArray(raw.refs) ? raw.refs : undefined,
    citations: Array.isArray(raw.citations) ? raw.citations : undefined,
  };
}

function mergeConversationMessages(
  prev: ChatMessageItem[],
  incoming: Array<Partial<ChatMessageItem>>
): ChatMessageItem[] {
  const prevById = new Map<string, ChatMessageItem>();
  const prevByApprovalId = new Map<string, ChatMessageItem>();
  for (const item of prev) {
    if (item.message_id) prevById.set(item.message_id, item);
    const apId = getMessageApprovalId(item);
    if (apId) prevByApprovalId.set(apId, item);
  }

  const merged: ChatMessageItem[] = [];
  const seenIds = new Set<string>();
  incoming.forEach((rawItem, idx) => {
    const raw = normalizeServerMessage(rawItem, idx);
    if (raw.message_id && seenIds.has(raw.message_id)) return;
    if (raw.message_id) seenIds.add(raw.message_id);

    const rawApId = getMessageApprovalId(raw);
    const existing =
      (raw.message_id ? prevById.get(raw.message_id) : undefined) ||
      (rawApId ? prevByApprovalId.get(rawApId) : undefined);

    const approvalNotice =
      raw.approvalNotice || raw.approval || existing?.approvalNotice || existing?.approval || undefined;
    const policyNotice = derivePolicyNotice(raw, existing);

    merged.push({
      ...raw,
      thinking: raw.thinking || existing?.thinking,
      citations: raw.citations?.length ? raw.citations : existing?.citations,
      ...(approvalNotice ? { approvalNotice } : {}),
      ...(policyNotice ? { policyNotice } : {}),
    });
  });
  return merged;
}

function coerceApprovalNotice(raw: unknown): ApprovalNoticeData | undefined {
  if (!raw || typeof raw !== "object") return undefined;
  const obj = raw as Record<string, unknown>;
  const approvalId = String(obj.approval_id || obj.id || "").trim();
  if (!approvalId) return undefined;
  return {
    approval_id: approvalId,
    action_type: String(obj.action_type || "action"),
    tool_name: String(obj.tool_name || "tool"),
    target: String(obj.target || ""),
    command_args: typeof obj.command_args === "string" ? obj.command_args : undefined,
    risk_tier: String(obj.risk_tier || "HIGH"),
    proposal_digest: typeof obj.proposal_digest === "string" ? obj.proposal_digest : undefined,
    rationale: typeof obj.rationale === "string" ? obj.rationale : undefined,
    status: typeof obj.status === "string" ? obj.status : "pending",
    decision_note: typeof obj.decision_note === "string" ? obj.decision_note : undefined,
    execution:
      obj.execution && typeof obj.execution === "object"
        ? (obj.execution as ApprovalExecutionResult)
        : undefined,
  };
}

function coerceCitations(raw: unknown): CopilotCitation[] {
  if (!Array.isArray(raw)) return [];
  const out: CopilotCitation[] = [];
  for (const item of raw) {
    if (!item || typeof item !== "object") continue;
    const rec = item as Record<string, unknown>;
    const id = String(rec.id || rec.ref_id || rec.source_id || "").trim();
    const label = String(rec.label || rec.title || id).trim();
    if (!id && !label) continue;
    out.push({
      kind: String(rec.kind || rec.type || "evidence"),
      id: id || label,
      label: label || id,
      excerpt: typeof rec.excerpt === "string" ? rec.excerpt : undefined,
    });
  }
  return out;
}

const COPILOT_MODES: Array<{ value: string; en: string; ar: string }> = [
  { value: "analyst", en: "analyst (Security Analyst)", ar: "analyst · محلل أمني" },
  { value: "redteam", en: "redteam (Operator)", ar: "redteam · مشغّل Red Team" },
  { value: "passive", en: "passive (Read-Only)", ar: "passive · تحليل سلبي" },
  { value: "recon", en: "recon (Recon & Surface)", ar: "recon · استطلاع وسطوح الهجوم" },
  { value: "triage", en: "triage (Findings Triage)", ar: "triage · فرز الأدلة والنتائج" },
];

interface InlineApprovalCardProps {
  notice: ApprovalNoticeData;
  storeRecord?: ApprovalItem;
  onDecide: (approvalId: string, decision: "approved" | "rejected", note: string) => Promise<void>;
  onInspect: (approvalId: string) => void;
  t: (key: string, params?: Record<string, string | number>) => string;
}

const InlineApprovalCard = React.memo(function InlineApprovalCard({
  notice,
  storeRecord,
  onDecide,
  onInspect,
  t,
}: InlineApprovalCardProps) {
  const [note, setNote] = useState<string>("");
  const [busy, setBusy] = useState<boolean>(false);

  const effectiveStatus = (storeRecord?.status || notice.status || "pending").toLowerCase();
  const isPending = effectiveStatus === "pending";
  const commandArgs = storeRecord?.command_args || notice.command_args || "";
  const digest = storeRecord?.proposal_digest || notice.proposal_digest || "";
  const riskTier = (storeRecord?.risk_tier || notice.risk_tier || "HIGH").toUpperCase();
  const execution = storeRecord?.execution || notice.execution || null;
  const decisionNote = storeRecord?.decision_note || notice.decision_note || "";

  const trigger = async (decision: "approved" | "rejected") => {
    setBusy(true);
    try {
      await onDecide(notice.approval_id, decision, note.trim());
    } finally {
      setBusy(false);
    }
  };

  return (
    <div
      data-testid={`copilot-approval-${notice.approval_id}`}
      className={`p-2.5 rounded-md border text-xs space-y-2 ${
        isPending
          ? "border-sentinel-warning/40 bg-sentinel-warning/10"
          : effectiveStatus === "approved"
            ? "border-sentinel-success/40 bg-sentinel-success/10"
            : "border-sentinel-danger/40 bg-sentinel-danger/10"
      }`}
    >
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div className="flex items-center gap-1.5 font-semibold text-ink-primary">
          <ShieldAlert className="w-3.5 h-3.5 text-sentinel-warning shrink-0" />
          <span>{t("copilot.approvalQueued")}</span>
        </div>
        <div className="flex items-center gap-1.5 font-mono text-[10px]">
          <span className="px-1.5 py-0.5 rounded bg-sentinel-danger/15 text-sentinel-danger border border-sentinel-danger/35 uppercase">
            {riskTier}
          </span>
          <span className="px-1.5 py-0.5 rounded bg-surface border border-border-subtle text-ink-secondary uppercase">
            {effectiveStatus}
          </span>
        </div>
      </div>

      <div className="font-mono text-[11px] text-ink-primary ltr-isolate break-all">
        {notice.action_type} · {notice.tool_name}
        {notice.target ? ` → ${notice.target}` : ""}
      </div>

      {commandArgs && (
        <div className="p-2 rounded bg-inset border border-border-subtle font-mono text-[11px] text-ink-secondary ltr-isolate overflow-x-auto">
          {sanitizePlainTerminalText(commandArgs)}
        </div>
      )}

      {digest && (
        <div className="font-mono text-[10px] text-ink-muted ltr-isolate truncate">
          {t("approvals.digestLabel")}: {digest}
        </div>
      )}

      {isPending ? (
        <div className="space-y-1.5 pt-1">
          <input
            type="text"
            value={note}
            onChange={(e) => setNote(e.target.value)}
            placeholder={t("approvals.notePlaceholder")}
            aria-label={t("approvals.notePlaceholder")}
            className="w-full h-8 px-2 rounded bg-inset border border-border-subtle text-xs text-ink-primary placeholder:text-ink-muted"
          />
          <div className="flex flex-wrap items-center gap-1.5">
            <button
              type="button"
              disabled={busy}
              onClick={() => void trigger("approved")}
              className="min-h-[36px] sm:min-h-[30px] px-2.5 rounded bg-sentinel-success text-white font-semibold text-xs flex items-center gap-1 hover:opacity-90 disabled:opacity-50"
            >
              {busy ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Check className="w-3.5 h-3.5" />}
              <span>{t("approvals.approveBtn")}</span>
            </button>
            <button
              type="button"
              disabled={busy}
              onClick={() => void trigger("rejected")}
              className="min-h-[36px] sm:min-h-[30px] px-2.5 rounded bg-sentinel-danger/15 border border-sentinel-danger/40 text-sentinel-danger font-semibold text-xs flex items-center gap-1 hover:bg-sentinel-danger/25 disabled:opacity-50"
            >
              <XCircle className="w-3.5 h-3.5" />
              <span>{t("approvals.rejectBtn")}</span>
            </button>
            <button
              type="button"
              onClick={() => onInspect(notice.approval_id)}
              className="ms-auto text-[11px] font-mono text-sentinel-primary hover:underline"
            >
              {t("common.details")}
            </button>
          </div>
        </div>
      ) : (
        <div className="space-y-1.5 pt-1 border-t border-border-subtle/70">
          {decisionNote && (
            <div className="text-[11px] text-ink-secondary">
              {t("approvals.noteLabel")}: {decisionNote}
            </div>
          )}
          {execution && (
            <div className="p-2 rounded bg-inset border border-border-subtle font-mono text-[11px] space-y-1 ltr-isolate">
              <div className="flex items-center justify-between text-[10px]">
                <span className={execution.executed && !execution.blocked ? "text-sentinel-success" : "text-sentinel-danger"}>
                  {execution.executed ? t("approvals.executedLabel") : t("approvals.notExecutedLabel")}
                </span>
                {typeof execution.returncode === "number" && (
                  <span className="text-ink-muted">exit={execution.returncode}</span>
                )}
              </div>
              {execution.stdout_excerpt && (
                <pre className="whitespace-pre-wrap break-words text-ink-primary max-h-28 overflow-y-auto">
                  {sanitizePlainTerminalText(execution.stdout_excerpt)}
                </pre>
              )}
              {execution.stderr_excerpt && (
                <pre className="whitespace-pre-wrap break-words text-sentinel-danger max-h-24 overflow-y-auto">
                  {sanitizePlainTerminalText(execution.stderr_excerpt)}
                </pre>
              )}
              {execution.error && (
                <div className="text-sentinel-danger">{execution.error}</div>
              )}
            </div>
          )}
        </div>
      )}
    </div>
  );
});

interface MessageRowProps {
  msg: ChatMessageItem;
  storeApproval?: ApprovalItem;
  onRefClick: (ref: CopilotRef) => void;
  onDecideApproval: (approvalId: string, decision: "approved" | "rejected", note: string) => Promise<void>;
  t: (key: string, params?: Record<string, string | number>) => string;
}

const CopilotMessageRow = React.memo(function CopilotMessageRow({
  msg,
  storeApproval,
  onRefClick,
  onDecideApproval,
  t,
}: MessageRowProps) {
  const [thinkingOpen, setThinkingOpen] = useState<boolean>(false);
  const isUser = msg.role === "user";
  const safeHtml = useMemo(
    () => (!isUser && msg.content ? renderSafeMarkdown(msg.content) : ""),
    [isUser, msg.content]
  );

  return (
    <div
      data-testid={`copilot-msg-${msg.role}`}
      className={`rounded-lg border p-3 space-y-2 ${
        isUser
          ? "bg-elevated border-border-strong ms-6"
          : "bg-inset border-border-subtle me-4"
      }`}
    >
      <div className="flex items-center justify-between gap-2 text-[11px] font-mono text-ink-muted">
        <span className={isUser ? "text-sentinel-primary font-semibold" : "text-sentinel-ai font-semibold"}>
          {isUser ? t("copilot.roleOperator") : t("copilot.roleCopilot")}
        </span>
        <div className="flex items-center gap-1.5 flex-wrap justify-end">
          {msg.metadata?.fallback && (
            <span className="px-1.5 py-0.5 rounded bg-sentinel-warning/15 text-sentinel-warning border border-sentinel-warning/35">
              {t("copilot.fallbackTag")}
            </span>
          )}
          {msg.metadata?.aborted && (
            <span className="px-1.5 py-0.5 rounded bg-sentinel-danger/15 text-sentinel-danger border border-sentinel-danger/35">
              {t("copilot.stoppedTag")}
            </span>
          )}
          {msg.model && <span className="ltr-isolate truncate max-w-[160px]">{msg.model}</span>}
        </div>
      </div>

      {/* Collapsible Thinking Block */}
      {!isUser && msg.thinking && (
        <div className="rounded border border-border-subtle bg-elevated/60 overflow-hidden">
          <button
            type="button"
            aria-expanded={thinkingOpen}
            onClick={() => setThinkingOpen((prev) => !prev)}
            className="w-full px-2.5 py-1.5 flex items-center justify-between gap-2 text-[11px] font-mono text-ink-secondary hover:text-ink-primary"
          >
            <span className="flex items-center gap-1.5">
              {thinkingOpen ? (
                <ChevronDown className="w-3.5 h-3.5 text-sentinel-ai" />
              ) : (
                <ChevronRight className="w-3.5 h-3.5 text-sentinel-ai rtl:rotate-180" />
              )}
              <Sparkles className="w-3 h-3 text-sentinel-ai" />
              <span>{t("copilot.thinkingLabel")}</span>
            </span>
            <span className="text-[10px] text-ink-muted tabular-nums">
              {msg.thinking.length} {t("copilot.charsUnit")}
            </span>
          </button>
          {thinkingOpen && (
            <pre className="px-2.5 pb-2.5 pt-1 border-t border-border-subtle text-[11px] font-mono text-ink-muted whitespace-pre-wrap break-words max-h-48 overflow-y-auto">
              {msg.thinking}
            </pre>
          )}
        </div>
      )}

      {msg.policyNotice && (
        <div className="p-2 rounded border border-sentinel-danger/40 bg-sentinel-danger/10 text-sentinel-danger text-xs flex items-start gap-1.5">
          <ShieldAlert className="w-4 h-4 shrink-0 mt-0.5" />
          <div>
            <div className="font-semibold">{t("copilot.policyBlocked")}</div>
            <div>{msg.policyNotice.reason}</div>
          </div>
        </div>
      )}

      {msg.approvalNotice && (
        <InlineApprovalCard
          notice={msg.approvalNotice}
          storeRecord={storeApproval}
          onDecide={onDecideApproval}
          onInspect={(approvalId) => onRefClick({ kind: "approval", id: approvalId })}
          t={t}
        />
      )}

      {isUser ? (
        <p className="text-sm text-ink-primary whitespace-pre-wrap break-words">{msg.content}</p>
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

      {/* Citations Pills */}
      {Array.isArray(msg.citations) && msg.citations.length > 0 && (
        <div className="pt-2 border-t border-border-subtle space-y-1">
          <div className="text-[10px] font-mono uppercase text-ink-muted flex items-center gap-1">
            <BookOpen className="w-3 h-3 text-sentinel-ai" />
            <span>{t("copilot.citationsTitle")}</span>
          </div>
          <div className="flex flex-wrap gap-1.5">
            {msg.citations.slice(0, 10).map((cit, idx) => (
              <button
                key={`${cit.kind}:${cit.id}-${idx}`}
                type="button"
                title={cit.excerpt || cit.label}
                onClick={() => onRefClick({ kind: cit.kind, id: cit.id, label: cit.label })}
                className="inline-flex items-center gap-1 px-2 py-0.5 rounded bg-sentinel-ai/10 border border-sentinel-ai/35 hover:border-sentinel-ai text-[11px] font-mono text-sentinel-ai ltr-isolate"
              >
                <BookOpen className="w-2.5 h-2.5 shrink-0" />
                <span className="truncate max-w-[180px]">{cit.label || `${cit.kind}:${cit.id}`}</span>
              </button>
            ))}
          </div>
        </div>
      )}

      {/* Referenced Records */}
      {Array.isArray(msg.refs) && msg.refs.length > 0 && (
        <div className="pt-2 border-t border-border-subtle space-y-1">
          <div className="text-[10px] font-mono uppercase text-ink-muted">
            {t("copilot.refsTitle")}
          </div>
          <div className="flex flex-wrap gap-1.5">
            {msg.refs.slice(0, 10).map((ref, refIdx) => (
              <button
                key={`${ref.kind}:${ref.id}-${refIdx}`}
                type="button"
                onClick={() => onRefClick(ref)}
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
});

export default function CopilotDrawer() {
  const {
    copilotOpen,
    setCopilotOpen,
    commandPaletteOpen,
    selectedEngagementId,
    runs,
    activeRunId,
    setActiveRunId,
    approvals,
    decideApproval,
    controlRun,
    recoverRun,
    hunterHubHealth,
    hunterFetch,
    navigateToRef,
    refreshNow,
  } = usePlatform();
  const { t, lang, dir } = useI18n();

  const [drawerWidth, setDrawerWidth] = useState<number>(460);
  const [fullWidth, setFullWidth] = useState<boolean>(false);
  const [conversations, setConversations] = useState<ConversationSummary[]>([]);
  const [activeConvId, setActiveConvId] = useState<string>("");
  const [pinnedRunId, setPinnedRunId] = useState<string>("auto");
  const [messages, setMessages] = useState<ChatMessageItem[]>([]);
  const [mode, setMode] = useState<string>("analyst");
  const [model, setModel] = useState<string>("auto");
  const [catalogModels, setCatalogModels] = useState<ModelChoiceItem[]>([]);
  const [catalogPolicy, setCatalogPolicy] = useState<string>("");
  const [catalogLoaded, setCatalogLoaded] = useState<boolean>(false);
  const [prompt, setPrompt] = useState<string>("");
  const [attachments, setAttachments] = useState<PendingAttachment[]>([]);
  const [isStreaming, setIsStreaming] = useState<boolean>(false);
  const [uploadingFile, setUploadingFile] = useState<boolean>(false);
  const [runActionBusy, setRunActionBusy] = useState<boolean>(false);
  const [statusNote, setStatusNote] = useState<string>("");

  const streamAbortRef = useRef<AbortController | null>(null);
  const streamNonceRef = useRef<number>(0);
  const deltaContentBufRef = useRef<string>("");
  const deltaThinkingBufRef = useRef<string>("");
  const deltaFallbackRef = useRef<boolean>(false);
  const deltaFlushTimerRef = useRef<number | null>(null);
  const fileInputRef = useRef<HTMLInputElement | null>(null);
  const activeConvIdRef = useRef<string>(activeConvId);
  const isStreamingRef = useRef<boolean>(isStreaming);
  const tempMsgSeqRef = useRef<number>(0);

  const { containerRef: scrollContainerRef, endRef: messagesEndRef, hasNewMessages, unreadCount, scrollToEnd } =
    useAutoScroll(messages, activeConvId || "new");

  useEffect(() => {
    activeConvIdRef.current = activeConvId;
  }, [activeConvId]);

  useEffect(() => {
    isStreamingRef.current = isStreaming;
  }, [isStreaming]);

  const stopActiveStream = useCallback((markAbortedMessageId?: string) => {
    streamNonceRef.current += 1;
    if (deltaFlushTimerRef.current !== null) {
      window.clearInterval(deltaFlushTimerRef.current);
      deltaFlushTimerRef.current = null;
    }
    deltaContentBufRef.current = "";
    deltaThinkingBufRef.current = "";
    deltaFallbackRef.current = false;

    if (streamAbortRef.current) {
      streamAbortRef.current.abort();
      streamAbortRef.current = null;
    }
    isStreamingRef.current = false;
    setIsStreaming(false);

    if (markAbortedMessageId) {
      setMessages((prev) =>
        prev.map((m) =>
          m.message_id === markAbortedMessageId
            ? {
                ...m,
                streaming: false,
                metadata: { ...m.metadata, aborted: true },
              }
            : m
        )
      );
    }
  }, []);

  // Abort cleanly on unmount so no deltas leak
  useEffect(() => {
    return () => {
      stopActiveStream();
    };
  }, [stopActiveStream]);

  const activeRunsCount = useMemo(
    () =>
      runs.filter((r) => ["running", "paused", "pending"].includes((r.status || "").toLowerCase()))
        .length,
    [runs]
  );

  const selectedMissionRun = useMemo<MissionRun | null>(() => {
    if (pinnedRunId && pinnedRunId !== "auto") {
      const pinned = runs.find((r) => r.run_id === pinnedRunId);
      if (pinned) return pinned;
    }
    const isRunActive = (r: { status?: string }) =>
      ["running", "paused", "pending"].includes((r.status || "").toLowerCase());
    if (activeRunId) {
      const ctxMatch = runs.find((r) => r.run_id === activeRunId);
      if (ctxMatch) return ctxMatch;
    }
    return runs.find(isRunActive) || runs[0] || null;
  }, [runs, activeRunId, pinnedRunId]);

  const approvalsById = useMemo(() => {
    const map = new Map<string, ApprovalItem>();
    for (const item of approvals) {
      if (item.approval_id) map.set(item.approval_id, item);
    }
    return map;
  }, [approvals]);

  const isLocalOnlyLocked = catalogPolicy.toLowerCase() === "local_only";

  const loadModelsCatalog = useCallback(async () => {
    if (hunterHubHealth.status === "offline") return;
    const autoLabel = lang === "ar" ? "auto · تلقائي (الموجه الذكي)" : "auto (Smart Router)";
    try {
      const res = await hunterFetch("/api/models/catalog");
      if (!res.ok) return;
      const cat = (await res.json()) as ModelCatalogResponse;
      if (typeof cat.policy === "string") {
        setCatalogPolicy(cat.policy);
      }

      const list: ModelChoiceItem[] = [{ id: "auto", label: autoLabel, available: true }];
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
            supports_tools: ch.supports_tools,
            supports_thinking: ch.supports_thinking,
            context_window: ch.context_window,
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
              supports_tools: true,
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
            supports_tools: /qwen|llama3|mistral|deepseek/i.test(m),
            supports_thinking: /r1|qwq|thinking|deepseek/i.test(m),
          });
        }
      }

      setCatalogModels(list);
      setCatalogLoaded(true);
    } catch {
      // Fall back gracefully
    }
  }, [hunterHubHealth.status, hunterFetch, lang]);

  const modelOptions = useMemo<ModelChoiceItem[]>(() => {
    const autoLabel = lang === "ar" ? "auto · تلقائي (الموجه الذكي)" : "auto (Smart Router)";
    const list: ModelChoiceItem[] = [];
    const seen = new Set<string>();
    const pushUnique = (opt: ModelChoiceItem) => {
      if (!opt.id || seen.has(opt.id)) return;
      seen.add(opt.id);
      list.push(opt);
    };

    pushUnique({ id: "auto", label: autoLabel, available: true });

    if (catalogLoaded && catalogModels.length > 0) {
      for (const item of catalogModels) pushUnique(item);
    } else {
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
      pushUnique({ id: model, label: model, available: true });
    }
    return list;
  }, [catalogLoaded, catalogModels, hunterHubHealth.services, lang, model]);

  const selectedModelMeta = useMemo(
    () => modelOptions.find((m) => m.id === model) || null,
    [modelOptions, model]
  );

  const modeOptions = useMemo(() => {
    const opts = [...COPILOT_MODES];
    if (mode && !opts.some((m) => m.value === mode)) {
      opts.push({ value: mode, en: mode, ar: mode });
    }
    return opts;
  }, [mode]);

  const persistConversationPatch = useCallback(
    async (cid: string, patch: { mode?: string; model?: string; run_id?: string | null }) => {
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
        // Non-fatal
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
    const opt = modelOptions.find((m) => m.id === nextModel);
    if (isLocalOnlyLocked && opt?.kind === "cloud") {
      setStatusNote(t("copilot.localOnlyLockHint"));
      return;
    }
    setModel(nextModel);
    if (activeConvId) {
      setConversations((prev) =>
        prev.map((c) => (c.conversation_id === activeConvId ? { ...c, model: nextModel } : c))
      );
      void persistConversationPatch(activeConvId, { model: nextModel });
    }
  };

  const loadConversations = useCallback(async () => {
    if (hunterHubHealth.status === "offline") return;
    try {
      const qs = new URLSearchParams({ limit: "50" });
      if (selectedEngagementId) qs.set("engagement_id", selectedEngagementId);
      const res = await hunterFetch(`/api/copilot/conversations?${qs.toString()}`);
      if (!res.ok) return;
      const data = (await res.json()) as { conversations?: ConversationSummary[] };
      const list = Array.isArray(data.conversations) ? data.conversations : [];
      setConversations(list);
      if (!activeConvIdRef.current && list.length > 0) {
        activeConvIdRef.current = list[0].conversation_id;
        setActiveConvId(list[0].conversation_id);
      }
    } catch {
      // Hub unavailable
    }
  }, [hunterHubHealth.status, hunterFetch, selectedEngagementId]);

  const loadConversationMessages = useCallback(
    async (cid: string) => {
      if (!cid || hunterHubHealth.status === "offline") return;
      try {
        const res = await hunterFetch(`/api/copilot/conversations/${encodeURIComponent(cid)}`);
        if (!res.ok) return;
        const data = (await res.json()) as {
          conversation?: ConversationSummary;
          messages?: Array<Partial<ChatMessageItem>>;
        };
        if (activeConvIdRef.current !== cid || isStreamingRef.current) {
          return;
        }
        if (data.conversation) {
          setMode(data.conversation.mode || "analyst");
          setModel(data.conversation.model || "auto");
        }
        const incoming = Array.isArray(data.messages) ? data.messages : [];
        setMessages((prev) => mergeConversationMessages(prev, incoming));
      } catch {
        // Ignore load error
      }
    },
    [hunterHubHealth.status, hunterFetch]
  );

  useEffect(() => {
    if (copilotOpen && hunterHubHealth.status !== "offline") {
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
    if (!copilotOpen) return;
    const onKeyDown = (ev: KeyboardEvent) => {
      if (ev.key === "Escape" && !commandPaletteOpen) {
        setCopilotOpen(false);
      }
    };
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, [copilotOpen, commandPaletteOpen, setCopilotOpen]);

  const handleSelectConversation = (nextConvId: string) => {
    if (nextConvId === activeConvId) return;
    // Cancel active stream cleanly so zero deltas leak across threads
    stopActiveStream();
    activeConvIdRef.current = nextConvId;
    setActiveConvId(nextConvId);
    setMessages([]);
    setStatusNote("");
  };

  const handlePointerResize = (e: React.PointerEvent<HTMLDivElement>) => {
    if (fullWidth) return;
    e.preventDefault();
    const startX = e.clientX;
    const startW = drawerWidth;
    const sign = dir === "rtl" ? 1 : -1;

    const onMove = (moveEv: PointerEvent) => {
      const delta = (moveEv.clientX - startX) * sign;
      const next = Math.min(780, Math.max(360, startW + delta));
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
      setDrawerWidth((w) => Math.min(780, Math.max(360, w + (dir === "rtl" ? -step : step))));
    } else if (e.key === "ArrowRight") {
      e.preventDefault();
      setDrawerWidth((w) => Math.min(780, Math.max(360, w + (dir === "rtl" ? step : -step))));
    }
  };

  const handleNewConversation = async () => {
    stopActiveStream();
    setStatusNote("");
    try {
      const res = await hunterFetch("/api/copilot/conversations", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          title: t("copilot.defaultSessionTitle"),
          engagement_id: selectedEngagementId || null,
          run_id: selectedMissionRun?.run_id || null,
          mode,
          model,
          set_active: true,
        }),
      });
      if (!res.ok) return;
      const data = (await res.json()) as { conversation?: ConversationSummary };
      if (data.conversation) {
        activeConvIdRef.current = data.conversation.conversation_id;
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
    stopActiveStream();
    try {
      const res = await hunterFetch(`/api/copilot/conversations/${encodeURIComponent(activeConvId)}`, {
        method: "DELETE",
      });
      if (!res.ok) return;
      const remaining = conversations.filter((c) => c.conversation_id !== activeConvId);
      const nextId = remaining[0]?.conversation_id || "";
      activeConvIdRef.current = nextId;
      setConversations(remaining);
      setActiveConvId(nextId);
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
        setStatusNote(err?.detail || `${t("copilot.uploadFailed")} (${res.status})`);
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

  const handleRunControl = async (action: "pause" | "resume" | "stop" | "recover") => {
    if (!selectedMissionRun) return;
    setRunActionBusy(true);
    setStatusNote("");
    try {
      const res =
        action === "recover"
          ? await recoverRun(selectedMissionRun.run_id)
          : await controlRun(selectedMissionRun.run_id, action);
      if (!res.ok) {
        setStatusNote(res.error || t("runs.controlFailed"));
      }
    } finally {
      setRunActionBusy(false);
    }
  };

  const handleInlineApprovalDecision = useCallback(
    async (approvalId: string, decision: "approved" | "rejected", note: string) => {
      const res = await decideApproval(approvalId, decision, note);
      if (!res.ok) {
        setStatusNote(res.error || t("approvals.decisionFailed"));
        return;
      }
      setMessages((prev) =>
        prev.map((m) => {
          if (m.approvalNotice?.approval_id !== approvalId) return m;
          return {
            ...m,
            approvalNotice: {
              ...m.approvalNotice,
              status: res.approval?.status || decision,
              decision_note: res.approval?.decision_note || note,
              execution: res.execution || res.approval?.execution || m.approvalNotice.execution,
            },
          };
        })
      );
    },
    [decideApproval, t]
  );

  const activeTempAssistIdRef = useRef<string>("");

  const handleSend = async (ev?: React.FormEvent) => {
    if (ev) ev.preventDefault();
    const text = prompt.trim();
    if (!text || isStreaming) return;

    setStatusNote("");
    const attachmentIds = attachments.map((a) => a.attachment_id);

    const nowMs = Date.now();
    tempMsgSeqRef.current += 1;
    const uSeq = tempMsgSeqRef.current;
    tempMsgSeqRef.current += 1;
    const aSeq = tempMsgSeqRef.current;

    const tempUserId = `tmp-u-${nowMs}-${uSeq}`;
    const tempAssistId = `tmp-a-${nowMs}-${aSeq}`;
    activeTempAssistIdRef.current = tempAssistId;

    const tempUserMsg: ChatMessageItem = {
      id: tempUserId,
      message_id: tempUserId,
      role: "user",
      content: text,
    };
    const tempAssistMsg: ChatMessageItem = {
      id: tempAssistId,
      message_id: tempAssistId,
      role: "assistant",
      content: "",
      thinking: "",
      streaming: true,
      refs: [],
      citations: [],
    };

    stopActiveStream();
    const myNonce = streamNonceRef.current + 1;
    streamNonceRef.current = myNonce;

    isStreamingRef.current = true;
    setMessages((prev) => [...prev, tempUserMsg, tempAssistMsg]);
    setIsStreaming(true);

    const controller = new AbortController();
    streamAbortRef.current = controller;

    // 50ms delta batching flusher to avoid per-token React re-render storms
    const flushBufferedDeltas = () => {
      if (streamNonceRef.current !== myNonce) return;
      const cDelta = deltaContentBufRef.current;
      const tDelta = deltaThinkingBufRef.current;
      const fb = deltaFallbackRef.current;
      if (!cDelta && !tDelta) return;
      deltaContentBufRef.current = "";
      deltaThinkingBufRef.current = "";
      setMessages((prev) =>
        prev.map((m) =>
          m.message_id === tempAssistId
            ? {
                ...m,
                content: m.content + cDelta,
                thinking: (m.thinking || "") + tDelta,
                metadata: fb ? { ...m.metadata, fallback: true } : m.metadata,
              }
            : m
        )
      );
    };

    deltaFlushTimerRef.current = window.setInterval(flushBufferedDeltas, 50);

    let confirmedDone = false;

    try {
      const activeConv = conversations.find((c) => c.conversation_id === activeConvId);
      const effectiveRunId = selectedMissionRun?.run_id || activeConv?.run_id || null;
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
        if (streamNonceRef.current !== myNonce) return;
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
          activeConvIdRef.current = payload.conversation_id;
          setActiveConvId(payload.conversation_id);
        }

        if (eventName === "start") {
          const startedModel = typeof payload.model === "string" ? payload.model : undefined;
          if (startedModel) {
            setMessages((prev) =>
              prev.map((m) => (m.message_id === tempAssistId ? { ...m, model: startedModel } : m))
            );
          }
        } else if (eventName === "context" || eventName === "refs") {
          const refs = Array.isArray(payload.refs) ? (payload.refs as CopilotRef[]) : [];
          setMessages((prev) =>
            prev.map((m) => (m.message_id === tempAssistId ? { ...m, refs } : m))
          );
        } else if (eventName === "citations") {
          const citations = coerceCitations(payload.citations ?? payload.items);
          if (citations.length > 0) {
            setMessages((prev) =>
              prev.map((m) => (m.message_id === tempAssistId ? { ...m, citations } : m))
            );
          }
        } else if (eventName === "approval_request" || eventName === "approval_required") {
          const ap = coerceApprovalNotice(payload.approval ?? payload);
          if (ap) {
            setMessages((prev) =>
              prev.map((m) =>
                m.message_id === tempAssistId
                  ? { ...m, approval_id: ap.approval_id, approvalNotice: ap }
                  : m
              )
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
        } else if (eventName === "thinking") {
          const delta =
            typeof payload.delta === "string"
              ? payload.delta
              : typeof payload.text === "string"
                ? payload.text
                : "";
          if (delta) {
            deltaThinkingBufRef.current += delta;
          }
        } else if (eventName === "token") {
          const delta = typeof payload.delta === "string" ? payload.delta : "";
          if (payload.fallback) deltaFallbackRef.current = true;
          if (delta) {
            deltaContentBufRef.current += delta;
          }
        } else if (eventName === "done") {
          flushBufferedDeltas();
          confirmedDone = true;
          const answer = typeof payload.answer === "string" ? payload.answer : "";
          const refs = Array.isArray(payload.refs) ? (payload.refs as CopilotRef[]) : [];
          const citations = coerceCitations(payload.citations);
          const provider = typeof payload.provider === "string" ? payload.provider : "";
          const modelUsed = typeof payload.model_used === "string" ? payload.model_used : "";
          const fallback = Boolean(payload.fallback);
          const serverMsg = payload.message as Partial<ChatMessageItem> | undefined;
          const serverMsgId =
            typeof serverMsg?.message_id === "string" && serverMsg.message_id
              ? serverMsg.message_id
              : "";
          const serverApproval = coerceApprovalNotice(payload.approval);
          const serverPolicy =
            (payload.policy as { allowed?: boolean; status?: string; reason?: string } | undefined) ||
            undefined;

          setMessages((prev) =>
            prev.map((m) => {
              if (m.message_id !== tempAssistId) return m;
              const nextId =
                serverMsgId && !prev.some((other) => other !== m && other.message_id === serverMsgId)
                  ? serverMsgId
                  : m.message_id;
              const nextApprovalNotice = m.approvalNotice || serverApproval;
              const nextPolicyNotice =
                m.policyNotice ||
                (serverPolicy && serverPolicy.allowed === false
                  ? {
                      allowed: false,
                      status: String(serverPolicy.status || "BLOCKED"),
                      reason: String(serverPolicy.reason || "Blocked by PolicyEngine"),
                    }
                  : undefined);
              return {
                ...m,
                id: nextId,
                message_id: nextId,
                content: answer || m.content,
                model: modelUsed || m.model,
                approval_id: serverMsg?.approval_id ?? m.approval_id ?? nextApprovalNotice?.approval_id,
                refs: refs.length > 0 ? refs : m.refs,
                citations: citations.length > 0 ? citations : m.citations,
                streaming: false,
                ...(nextApprovalNotice ? { approvalNotice: nextApprovalNotice } : {}),
                ...(nextPolicyNotice ? { policyNotice: nextPolicyNotice } : {}),
                metadata: {
                  ...m.metadata,
                  provider,
                  fallback,
                  ...(serverPolicy ? { policy_outcome: serverPolicy } : {}),
                },
              };
            })
          );

          // Clear prompt & attachment chips ONLY on confirmed completion
          setPrompt("");
          setAttachments([]);
          void loadConversations();
        } else if (eventName === "error") {
          flushBufferedDeltas();
          const errText = typeof payload.error === "string" ? payload.error : t("copilot.streamError");
          setStatusNote(errText);
          setMessages((prev) =>
            prev.map((m) =>
              m.message_id === tempAssistId
                ? { ...m, content: m.content || errText, streaming: false }
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
        if (streamNonceRef.current !== myNonce) break;
        if (done) {
          buffer += decoder.decode();
          break;
        }
        buffer += decoder.decode(value, { stream: true });
        flushCompleteBlocks();
      }

      if (streamNonceRef.current === myNonce) {
        flushCompleteBlocks();
        if (buffer.trim()) {
          processBlock(buffer);
          buffer = "";
        }
        flushBufferedDeltas();

        setMessages((prev) =>
          prev.map((m) =>
            m.message_id === tempAssistId && m.streaming ? { ...m, streaming: false } : m
          )
        );

        if (confirmedDone && streamConvId && !conversations.some((c) => c.conversation_id === streamConvId)) {
          void loadConversations();
        }
      }
    } catch (err) {
      if (!controller.signal.aborted && streamNonceRef.current === myNonce) {
        const msg = err instanceof Error ? err.message : t("copilot.offlineBanner");
        setStatusNote(msg);
        setMessages((prev) =>
          prev.map((m) =>
            m.message_id === tempAssistId
              ? { ...m, content: m.content || msg, streaming: false }
              : m
          )
        );
      }
      // Draft & attachments deliberately preserved on error/abort!
    } finally {
      if (streamNonceRef.current === myNonce) {
        if (deltaFlushTimerRef.current !== null) {
          window.clearInterval(deltaFlushTimerRef.current);
          deltaFlushTimerRef.current = null;
        }
        streamAbortRef.current = null;
        isStreamingRef.current = false;
        setIsStreaming(false);
      }
    }
  };

  const handleRefClick = useCallback(
    (ref: CopilotRef) => {
      const handled = navigateToRef(ref);
      if (!handled) {
        setStatusNote(`${t("copilot.refMissing")} (${ref.kind}: ${ref.id})`);
      } else {
        setStatusNote("");
      }
    },
    [navigateToRef, t]
  );

  if (!copilotOpen) {
    return null;
  }

  const runProgressPct = selectedMissionRun
    ? normalizeRunProgressPercent(selectedMissionRun.progress)
    : 0;
  const runStatusLower = (selectedMissionRun?.status || "").toLowerCase();
  const canRecoverRun =
    Boolean(selectedMissionRun) &&
    (selectedMissionRun?.recoverable ||
      ["paused", "interrupted", "failed", "stopped"].includes(runStatusLower));

  return (
    <aside
      role="dialog"
      aria-modal="false"
      aria-labelledby="copilot-drawer-title"
      data-testid="copilot-drawer"
      style={fullWidth ? { width: "100vw" } : { width: `min(100vw, ${drawerWidth}px)` }}
      className="fixed inset-y-0 end-0 z-50 bg-surface border-s border-border-strong shadow-sentinelMd flex flex-col"
    >
      {/* Drag & Keyboard Resize Handle */}
      {!fullWidth && (
        <div
          role="separator"
          aria-orientation="vertical"
          aria-label={t("copilot.resizeDrawer")}
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
                  {activeRunsCount} {t("states.active")}
                </span>
              )}
              {isLocalOnlyLocked && (
                <span
                  data-testid="copilot-local-lock"
                  className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded bg-sentinel-success/15 text-sentinel-success border border-sentinel-success/35 text-[10px]"
                >
                  <Lock className="w-2.5 h-2.5" />
                  <span>{t("copilot.localOnlyLock")}</span>
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
            className="min-h-[44px] min-w-[44px] sm:min-h-[32px] sm:min-w-[32px] rounded border border-border-subtle bg-elevated text-ink-secondary hover:text-ink-primary flex items-center justify-center"
          >
            {fullWidth ? <Minimize2 className="w-4 h-4" /> : <Maximize2 className="w-4 h-4" />}
          </button>

          <button
            type="button"
            onClick={() => setCopilotOpen(false)}
            aria-label={t("common.close")}
            className="min-h-[44px] min-w-[44px] sm:min-h-[32px] sm:min-w-[32px] rounded border border-border-subtle bg-elevated text-ink-secondary hover:text-ink-primary flex items-center justify-center"
          >
            <X className="w-4 h-4" />
          </button>
        </div>
      </div>

      {/* Pinned Mission / Run Control Bar */}
      <div className="px-4 py-2 border-b border-border-subtle bg-inset/80 space-y-1.5">
        <div className="flex items-center gap-1.5">
          <label htmlFor="copilot-run-selector" className="text-[11px] font-mono text-ink-muted shrink-0">
            {t("copilot.missionScope")}:
          </label>
          <select
            id="copilot-run-selector"
            value={pinnedRunId}
            onChange={(e) => {
              const nextVal = e.target.value;
              setPinnedRunId(nextVal);
              if (nextVal !== "auto") {
                setActiveRunId(nextVal);
              }
            }}
            className="flex-1 min-w-0 h-7 px-2 rounded bg-surface border border-border-subtle text-[11px] font-mono text-ink-primary ltr-isolate truncate"
          >
            <option value="auto">{t("copilot.autoFollowRun")}</option>
            {runs.map((r, idx) => (
              <option key={`${r.run_id}-${idx}`} value={r.run_id}>
                {r.run_id} · {r.target || r.kind} ({r.status})
              </option>
            ))}
          </select>
        </div>

        {selectedMissionRun && (
          <div className="space-y-1.5">
            <div className="flex items-center justify-between gap-2 text-[11px] font-mono">
              <span className="text-ink-secondary truncate ltr-isolate">
                {selectedMissionRun.current_phase || selectedMissionRun.kind} ·{" "}
                <strong className="text-ink-primary tabular-nums">{runProgressPct}%</strong>
              </span>
              <div className="flex items-center gap-1 shrink-0">
                {runStatusLower === "running" && (
                  <button
                    type="button"
                    disabled={runActionBusy}
                    onClick={() => void handleRunControl("pause")}
                    aria-label={t("runs.pauseRun")}
                    title={t("runs.pauseRun")}
                    className="h-6 px-2 rounded border border-border-subtle bg-elevated hover:border-sentinel-warning text-sentinel-warning flex items-center gap-1 disabled:opacity-40"
                  >
                    <Pause className="w-3 h-3" />
                    <span className="hidden sm:inline">{t("runs.pauseRun")}</span>
                  </button>
                )}
                {runStatusLower === "paused" && (
                  <button
                    type="button"
                    disabled={runActionBusy}
                    onClick={() => void handleRunControl("resume")}
                    aria-label={t("runs.resumeRun")}
                    title={t("runs.resumeRun")}
                    className="h-6 px-2 rounded border border-border-subtle bg-elevated hover:border-sentinel-success text-sentinel-success flex items-center gap-1 disabled:opacity-40"
                  >
                    <Play className="w-3 h-3" />
                    <span className="hidden sm:inline">{t("runs.resumeRun")}</span>
                  </button>
                )}
                {["running", "paused", "pending"].includes(runStatusLower) && (
                  <button
                    type="button"
                    disabled={runActionBusy}
                    onClick={() => void handleRunControl("stop")}
                    aria-label={t("runs.stopRun")}
                    title={t("runs.stopRun")}
                    className="h-6 px-2 rounded border border-border-subtle bg-elevated hover:border-sentinel-danger text-sentinel-danger flex items-center gap-1 disabled:opacity-40"
                  >
                    <Square className="w-3 h-3" />
                    <span className="hidden sm:inline">{t("runs.stopRun")}</span>
                  </button>
                )}
                {canRecoverRun && (
                  <button
                    type="button"
                    disabled={runActionBusy}
                    onClick={() => void handleRunControl("recover")}
                    aria-label={t("runs.recoverRun")}
                    title={t("runs.recoverRun")}
                    className="h-6 px-2 rounded border border-sentinel-primary/40 bg-sentinel-primary/15 text-sentinel-primary flex items-center gap-1 disabled:opacity-40"
                  >
                    <RotateCcw className="w-3 h-3" />
                    <span className="hidden sm:inline">{t("runs.recoverRun")}</span>
                  </button>
                )}
              </div>
            </div>
            <div
              role="progressbar"
              aria-label={t("runs.targetProgress")}
              aria-valuemin={0}
              aria-valuemax={100}
              aria-valuenow={runProgressPct}
              className="w-full h-1.5 rounded-full bg-elevated border border-border-subtle overflow-hidden"
            >
              <div
                className="h-full bg-sentinel-primary transition-[width] duration-300"
                style={{ width: `${runProgressPct}%` }}
              />
            </div>
          </div>
        )}
      </div>

      {/* Session, Mode & Model Picker Controls */}
      <div className="px-4 py-2.5 border-b border-border-subtle bg-elevated/60 space-y-2">
        <div className="flex items-center gap-1.5">
          <select
            value={activeConvId}
            onChange={(e) => handleSelectConversation(e.target.value)}
            aria-label={t("copilot.conversationSelect")}
            className="flex-1 min-w-0 h-8 px-2 rounded bg-inset border border-border-subtle text-xs text-ink-primary truncate"
          >
            {conversations.length === 0 && <option value="">{t("copilot.newSession")}</option>}
            {conversations.map((c, idx) => (
              <option key={`${c.conversation_id || "conv"}-${idx}`} value={c.conversation_id}>
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
              {modelOptions.map((opt) => {
                const blockedByLocalPolicy = isLocalOnlyLocked && opt.kind === "cloud";
                return (
                  <option key={opt.id} value={opt.id} disabled={blockedByLocalPolicy}>
                    {opt.label}
                    {blockedByLocalPolicy ? ` (${t("copilot.localOnlyLock")})` : ""}
                  </option>
                );
              })}
            </select>
          </label>
        </div>

        {/* Model Capability Badges */}
        {selectedModelMeta && selectedModelMeta.id !== "auto" && (
          <div className="flex flex-wrap items-center gap-1.5 text-[10px] font-mono">
            <span
              className={`inline-flex items-center gap-1 px-1.5 py-0.5 rounded border ${
                selectedModelMeta.kind === "local"
                  ? "bg-sentinel-success/15 text-sentinel-success border-sentinel-success/35"
                  : "bg-sentinel-primary/15 text-sentinel-primary border-sentinel-primary/35"
              }`}
            >
              <Cpu className="w-2.5 h-2.5" />
              <span>
                {selectedModelMeta.kind === "local"
                  ? t("models.localPrivateBadge")
                  : t("models.cloudFallbackBadge")}
              </span>
            </span>
            {selectedModelMeta.supports_tools && (
              <span className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded bg-elevated border border-border-subtle text-ink-secondary">
                <Wrench className="w-2.5 h-2.5 text-sentinel-primary" />
                <span>{t("copilot.capTools")}</span>
              </span>
            )}
            {selectedModelMeta.supports_thinking && (
              <span className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded bg-sentinel-ai/15 border border-sentinel-ai/35 text-sentinel-ai">
                <Sparkles className="w-2.5 h-2.5" />
                <span>{t("copilot.capThinking")}</span>
              </span>
            )}
          </div>
        )}
      </div>

      {/* Offline / Status Banner */}
      {(hunterHubHealth.status === "offline" || statusNote) && (
        <div
          role="status"
          className="mx-4 mt-3 px-3 py-2 rounded-md border border-sentinel-warning/40 bg-sentinel-warning/10 text-sentinel-warning text-xs"
        >
          {hunterHubHealth.status === "offline" ? t("copilot.offlineBanner") : statusNote}
        </div>
      )}

      {/* Messages with Sticky Auto-Scroll */}
      <div className="relative flex-1 min-h-0">
        <div ref={scrollContainerRef} className="h-full overflow-y-auto p-4 space-y-3">
          {messages.length === 0 ? (
            <div className="h-full flex flex-col items-center justify-center text-center px-4 text-ink-muted space-y-2">
              <Bot className="w-10 h-10 text-sentinel-ai opacity-50" />
              <p className="text-xs leading-relaxed max-w-xs">{t("copilot.noConversations")}</p>
            </div>
          ) : (
            messages.map((msg) => {
              const apId = getMessageApprovalId(msg);
              return (
                <CopilotMessageRow
                  key={msg.message_id}
                  msg={msg}
                  storeApproval={apId ? approvalsById.get(apId) : undefined}
                  onRefClick={handleRefClick}
                  onDecideApproval={handleInlineApprovalDecision}
                  t={t}
                />
              );
            })
          )}
          <div ref={messagesEndRef} />
        </div>

        {hasNewMessages && (
          <button
            type="button"
            onClick={() => scrollToEnd("smooth")}
            className="absolute end-4 bottom-4 z-10 inline-flex items-center gap-1.5 px-3 py-1.5 rounded-full bg-sentinel-primary text-sentinel-onAccent text-xs font-semibold shadow-sentinelMd hover:opacity-95"
          >
            <ArrowDown className="w-3.5 h-3.5" />
            <span>{t("copilot.unreadMessages", { count: unreadCount })}</span>
          </button>
        )}
      </div>

      {/* Composer */}
      <form onSubmit={handleSend} className="p-3 border-t border-border-subtle bg-surface space-y-2">
        {attachments.length > 0 && (
          <div className="flex flex-wrap gap-1.5">
            {attachments.map((att, attIdx) => (
              <span
                key={`${att.attachment_id || "att"}-${attIdx}`}
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
                  aria-label={`${t("common.delete")} ${att.filename}`}
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
            disabled={uploadingFile || isStreaming || hunterHubHealth.status === "offline"}
            onClick={() => fileInputRef.current?.click()}
            title={t("copilot.attachBtn")}
            aria-label={t("copilot.attachBtn")}
            className="min-h-[44px] min-w-[44px] sm:min-h-[36px] sm:min-w-[36px] rounded-md border border-border-subtle bg-elevated hover:border-border-strong text-ink-secondary hover:text-ink-primary flex items-center justify-center shrink-0 disabled:opacity-40"
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
                if (!isStreaming) void handleSend();
              }
            }}
            placeholder={t("copilot.placeholder")}
            aria-label={t("copilot.placeholder")}
            className="flex-1 px-3 py-2 rounded-md bg-inset border border-border-subtle text-xs text-ink-primary placeholder:text-ink-muted resize-none focus:border-sentinel-primary"
          />

          {isStreaming ? (
            <button
              type="button"
              data-testid="copilot-stop-btn"
              onClick={() => stopActiveStream(activeTempAssistIdRef.current)}
              aria-label={t("copilot.stopBtn")}
              title={t("copilot.stopBtn")}
              className="min-h-[44px] sm:min-h-[36px] px-3.5 rounded-md bg-sentinel-danger text-white text-xs font-semibold flex items-center gap-1.5 hover:opacity-90 shrink-0"
            >
              <Square className="w-3.5 h-3.5 fill-current" />
              <span>{t("common.stop")}</span>
            </button>
          ) : (
            <button
              type="submit"
              data-testid="copilot-send-btn"
              disabled={!prompt.trim() || hunterHubHealth.status === "offline"}
              aria-label={t("copilot.sendBtn")}
              className="min-h-[44px] sm:min-h-[36px] px-3.5 rounded-md bg-sentinel-primary text-sentinel-onAccent text-xs font-semibold flex items-center gap-1.5 hover:opacity-90 disabled:opacity-40 shrink-0"
            >
              <Send className="w-4 h-4 rtl:rotate-180" />
            </button>
          )}
        </div>
      </form>
    </aside>
  );
}
