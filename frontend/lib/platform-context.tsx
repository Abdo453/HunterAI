"use client";

import React, {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useRef,
  useState,
} from "react";

export const ARTEX_API_BASE = (
  process.env.NEXT_PUBLIC_ARTEX_API_BASE || "http://127.0.0.1:7071/api/v1"
).replace(/\/+$/, "");

export const HUNTER_API_BASE = (
  process.env.NEXT_PUBLIC_HUNTER_API_BASE || "http://127.0.0.1:8000"
).replace(/\/+$/, "");

export interface AssetRecord {
  id: string;
  target_id?: string;
  kind: string;
  value: string;
  attributes: Record<string, unknown>;
  first_seen?: string | null;
  created_at?: string | null;
}

export interface FindingRecord {
  id: string;
  engagement_id?: string;
  target_id?: string;
  title: string;
  vuln_class: string;
  severity: string;
  cvss_score: number;
  confidence: number;
  endpoint: string;
  evidence: string;
  poc_details?: Record<string, unknown>;
  poc_script?: string;
  status: string;
  created_at?: string | null;
}

export interface TaskRecord {
  id: string;
  engagement_id?: string;
  agent_role: string;
  title: string;
  status: string;
  priority: number;
  input_context: Record<string, unknown>;
  output_summary: Record<string, unknown>;
  created_at?: string | null;
  updated_at?: string | null;
}

export interface AuditRecord {
  id: string;
  engagement_id?: string;
  actor: string;
  action: string;
  details: Record<string, unknown>;
  created_at?: string | null;
}

export interface EngagementRecord {
  id: string;
  name: string;
  target: string;
  code?: string;
  in_scope: string[];
  out_of_scope: string[];
  status: string;
  source: string;
  isGoUuid: boolean;
  created_at?: string | null;
}

export interface RunRecord {
  run_id: string;
  kind: string;
  target: string;
  engagement_id?: string | null;
  status: string;
  current_phase?: string;
  progress?: number;
  error?: string;
  started_at?: number | null;
  finished_at?: number | null;
  created_at?: number | null;
  meta?: Record<string, unknown>;
}

export interface ApprovalRecord {
  approval_id: string;
  engagement_id?: string | null;
  run_id?: string | null;
  conversation_id?: string | null;
  task_id?: string | null;
  action_type: string;
  target: string;
  tool_name: string;
  command_args: string;
  risk_tier: string;
  rationale: string;
  status: string;
  decision_note?: string;
  decided_by?: string;
  decided_at?: number | null;
  created_at: number;
}

export interface StatsSummary {
  total_assets: number;
  total_findings: number;
  total_engagements: number;
  status: string;
  error?: string;
}

export type ServiceConnectivity = "connected" | "degraded" | "offline" | "checking";

export interface GoCoreHealth {
  status: ServiceConnectivity;
  database: "connected" | "disconnected" | "unknown";
  engine?: string;
  error?: string;
  lastSyncedAt: number | null;
  viaBridge?: boolean;
}

export interface HunterHubHealth {
  status: "connected" | "offline" | "checking";
  error?: string;
  lastSyncedAt: number | null;
  latestSeq: number;
  services?: {
    ollama?: { online: boolean; host?: string };
    lm_studio?: { online: boolean; host?: string };
    cloud_providers?: string[];
    burp_proxy?: { online: boolean; host?: string };
    burp_agent?: { online: boolean; host?: string };
  };
}

export type ConsoleLevel = "INFO" | "SUCCESS" | "WARN" | "ERROR" | "AUDIT";

export interface ConsoleEntry {
  id: string;
  timestamp: string;
  level: ConsoleLevel;
  source: string;
  message: string;
}

export interface CopilotRef {
  kind: string;
  id: string;
  label?: string;
  section?: string;
}

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

function isPrivateOrLocalHost(host: string): boolean {
  const h = host.toLowerCase().replace(/^\[|\]$/g, "");
  if (
    h === "localhost" ||
    h.endsWith(".local") ||
    h.endsWith(".internal") ||
    h === "metadata.google.internal" ||
    h === "0.0.0.0" ||
    h === "::1" ||
    h === "::"
  ) {
    return true;
  }
  if (/^127\./.test(h)) return true;
  if (/^10\./.test(h)) return true;
  if (/^169\.254\./.test(h)) return true;
  if (/^192\.168\./.test(h)) return true;
  if (/^172\.(1[6-9]|2\d|3[01])\./.test(h)) return true;
  if (/^(fe80|fc00|fd00):/i.test(h)) return true;
  return false;
}

export type TargetValidationReason =
  | "empty"
  | "invalid_format"
  | "blocked_local"
  | "out_of_scope"
  | "not_in_scope";

export interface TargetValidationResult {
  valid: boolean;
  normalizedTarget: string;
  hostname: string;
  reason?: TargetValidationReason;
}

function matchesScopePattern(hostname: string, pattern: string): boolean {
  const clean = pattern
    .trim()
    .toLowerCase()
    .replace(/^https?:\/\//, "")
    .split("/")[0]
    .split(":")[0];
  if (!clean) return false;
  if (clean.startsWith("*.")) {
    const base = clean.slice(2);
    return hostname === base || hostname.endsWith(`.${base}`);
  }
  return hostname === clean || hostname.endsWith(`.${clean}`);
}

export function validateScanTarget(
  rawInput: string,
  engagement?: EngagementRecord | null
): TargetValidationResult {
  const trimmed = rawInput.trim();
  if (!trimmed) {
    return { valid: false, normalizedTarget: "", hostname: "", reason: "empty" };
  }
  if (/[\s"'`<>|;&$()]/.test(trimmed)) {
    return { valid: false, normalizedTarget: "", hostname: "", reason: "invalid_format" };
  }

  let parsed: URL;
  try {
    parsed = new URL(trimmed.includes("://") ? trimmed : `https://${trimmed}`);
  } catch {
    return { valid: false, normalizedTarget: "", hostname: "", reason: "invalid_format" };
  }

  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
    return { valid: false, normalizedTarget: "", hostname: "", reason: "invalid_format" };
  }

  const hostname = parsed.hostname.toLowerCase();
  if (!hostname || (!hostname.includes(".") && !hostname.includes(":"))) {
    return { valid: false, normalizedTarget: "", hostname, reason: "invalid_format" };
  }

  if (isPrivateOrLocalHost(hostname)) {
    return { valid: false, normalizedTarget: hostname, hostname, reason: "blocked_local" };
  }

  if (engagement) {
    if (engagement.out_of_scope.some((rule) => matchesScopePattern(hostname, rule))) {
      return { valid: false, normalizedTarget: hostname, hostname, reason: "out_of_scope" };
    }
    if (
      engagement.in_scope.length > 0 &&
      !engagement.in_scope.some((rule) => matchesScopePattern(hostname, rule))
    ) {
      return { valid: false, normalizedTarget: hostname, hostname, reason: "not_in_scope" };
    }
  }

  return { valid: true, normalizedTarget: hostname, hostname };
}

function fingerprintData(value: unknown): string {
  try {
    return JSON.stringify(value);
  } catch {
    return String(Date.now());
  }
}

function formatTimeHHMMSS(ts?: string | number | null): string {
  if (!ts) return new Date().toLocaleTimeString("en-GB", { hour12: false });
  const d = typeof ts === "number" ? new Date(ts * 1000) : new Date(ts);
  if (Number.isNaN(d.getTime())) {
    return new Date().toLocaleTimeString("en-GB", { hour12: false });
  }
  return d.toLocaleTimeString("en-GB", { hour12: false });
}

interface PlatformContextValue {
  engagements: EngagementRecord[];
  selectedEngagementId: string;
  selectedEngagement: EngagementRecord | null;
  selectEngagement: (id: string) => Promise<void>;
  targetDomain: string;
  setTargetDomain: (target: string) => void;
  stats: StatsSummary;
  assets: AssetRecord[];
  findings: FindingRecord[];
  tasks: TaskRecord[];
  auditLogs: AuditRecord[];
  runs: RunRecord[];
  activeRunId: string | null;
  approvals: ApprovalRecord[];
  pendingApprovalsCount: number;
  goCoreHealth: GoCoreHealth;
  hunterHubHealth: HunterHubHealth;
  isLoading: boolean;
  isScanning: boolean;
  streamPaused: boolean;
  setStreamPaused: React.Dispatch<React.SetStateAction<boolean>>;
  consoleLogs: ConsoleEntry[];
  addConsoleLog: (level: ConsoleLevel, source: string, message: string, id?: string, ts?: string) => void;
  clearConsoleLogs: () => void;
  refreshNow: () => Promise<void>;
  launchScan: (target: string) => Promise<{ ok: boolean; error?: string; via?: string }>;
  decideApproval: (
    approvalId: string,
    decision: "approved" | "rejected",
    note?: string
  ) => Promise<{ ok: boolean; error?: string }>;
  controlRun: (
    runId: string,
    action: "pause" | "resume" | "stop"
  ) => Promise<{ ok: boolean; error?: string }>;
  inspectedAsset: AssetRecord | null;
  setInspectedAsset: (asset: AssetRecord | null) => void;
  inspectedFinding: FindingRecord | null;
  setInspectedFinding: (finding: FindingRecord | null) => void;
  copilotOpen: boolean;
  setCopilotOpen: React.Dispatch<React.SetStateAction<boolean>>;
  navigateToRef: (ref: CopilotRef) => boolean;
  hunterFetch: (path: string, init?: RequestInit) => Promise<Response>;
}

const PlatformContext = createContext<PlatformContextValue | null>(null);

export function PlatformProvider({ children }: { children: React.ReactNode }) {
  const [engagements, setEngagements] = useState<EngagementRecord[]>([]);
  const [selectedEngagementId, setSelectedEngagementId] = useState<string>("");
  const [targetDomain, setTargetDomain] = useState<string>("example.com");

  const [stats, setStats] = useState<StatsSummary>({
    total_assets: 0,
    total_findings: 0,
    total_engagements: 0,
    status: "CHECKING",
  });
  const [assets, setAssets] = useState<AssetRecord[]>([]);
  const [findings, setFindings] = useState<FindingRecord[]>([]);
  const [tasks, setTasks] = useState<TaskRecord[]>([]);
  const [auditLogs, setAuditLogs] = useState<AuditRecord[]>([]);
  const [runs, setRuns] = useState<RunRecord[]>([]);
  const [activeRunId, setActiveRunId] = useState<string | null>(null);
  const [approvals, setApprovals] = useState<ApprovalRecord[]>([]);

  const [goCoreHealth, setGoCoreHealth] = useState<GoCoreHealth>({
    status: "checking",
    database: "unknown",
    lastSyncedAt: null,
  });
  const [hunterHubHealth, setHunterHubHealth] = useState<HunterHubHealth>({
    status: "checking",
    lastSyncedAt: null,
    latestSeq: 0,
  });

  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [isScanning, setIsScanning] = useState<boolean>(false);
  const [streamPaused, setStreamPaused] = useState<boolean>(false);
  const [consoleLogs, setConsoleLogs] = useState<ConsoleEntry[]>([]);

  const [inspectedAsset, setInspectedAsset] = useState<AssetRecord | null>(null);
  const [inspectedFinding, setInspectedFinding] = useState<FindingRecord | null>(null);
  const [copilotOpen, setCopilotOpen] = useState<boolean>(false);

  const useProxyRef = useRef<boolean>(false);
  const pollAbortRef = useRef<AbortController | null>(null);
  const lastSeqRef = useRef<number>(0);
  const lastEventIdRef = useRef<string>("");
  const streamPausedRef = useRef<boolean>(false);
  const selectedEngRef = useRef<string>("");

  const fpRef = useRef<Record<string, string>>({});
  const seenAuditIdsRef = useRef<Set<string>>(new Set());
  const seenSseSeqRef = useRef<Set<number>>(new Set());

  useEffect(() => {
    streamPausedRef.current = streamPaused;
  }, [streamPaused]);

  useEffect(() => {
    selectedEngRef.current = selectedEngagementId;
  }, [selectedEngagementId]);

  const addConsoleLog = useCallback(
    (level: ConsoleLevel, source: string, message: string, customId?: string, ts?: string) => {
      setConsoleLogs((prev) => {
        if (customId && prev.some((item) => item.id === customId)) {
          return prev;
        }
        const nextEntry: ConsoleEntry = {
          id: customId || `${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
          timestamp: ts || new Date().toLocaleTimeString("en-GB", { hour12: false }),
          level,
          source,
          message,
        };
        return [...prev.slice(-199), nextEntry];
      });
    },
    []
  );

  const clearConsoleLogs = useCallback(() => {
    setConsoleLogs([]);
  }, []);

  /**
   * Fetch against FastAPI Hub, transparently falling back to the same-origin
   * `/api/hunter-proxy` bridge if cross-origin browser CORS blocks direct :8000 access.
   */
  const hunterFetch = useCallback(async (path: string, init?: RequestInit): Promise<Response> => {
    const normalized = path.startsWith("/") ? path : `/${path}`;
    const proxyUrl = `/api/hunter-proxy${normalized}`;
    const directUrl = `${HUNTER_API_BASE}${normalized}`;

    const isCrossOrigin =
      typeof window !== "undefined" &&
      (() => {
        try {
          return new URL(HUNTER_API_BASE, window.location.href).origin !== window.location.origin;
        } catch {
          return false;
        }
      })();

    if (useProxyRef.current && isCrossOrigin) {
      return fetch(proxyUrl, init);
    }

    try {
      const resp = await fetch(directUrl, init);
      return resp;
    } catch (err) {
      if (init?.signal?.aborted) {
        throw err;
      }
      if (isCrossOrigin) {
        const proxyResp = await fetch(proxyUrl, init);
        if (proxyResp.status !== 503) {
          useProxyRef.current = true;
        }
        return proxyResp;
      }
      throw err;
    }
  }, []);

  const refreshData = useCallback(async () => {
    if (typeof document !== "undefined" && document.hidden) {
      return;
    }

    if (pollAbortRef.current) {
      pollAbortRef.current.abort();
    }
    const controller = new AbortController();
    pollAbortRef.current = controller;
    const { signal } = controller;

    const currentEngId = selectedEngRef.current;
    const isGoUuid = UUID_RE.test(currentEngId);
    const goFilter = isGoUuid ? `?engagement_id=${encodeURIComponent(currentEngId)}` : "";

    const fetchJson = async (url: string, useHunter = false): Promise<{ ok: boolean; status: number; data: unknown }> => {
      try {
        const res = useHunter
          ? await hunterFetch(url, { signal, cache: "no-store" })
          : await fetch(url, { signal, cache: "no-store" });
        const text = await res.text();
        let data: unknown = null;
        if (text) {
          try {
            data = JSON.parse(text);
          } catch {
            data = { raw: text };
          }
        }
        return { ok: res.ok, status: res.status, data };
      } catch {
        return { ok: false, status: 0, data: null };
      }
    };

    try {
      const [
        goHealthRes,
        goStatsRes,
        goEngsRes,
        goAssetsRes,
        goFindingsRes,
        goTasksRes,
        goAuditRes,
        hubOverviewRes,
        hubArtexHealthRes,
        hubApprovalsRes,
        hubRunsRes,
      ] = await Promise.all([
        fetchJson(`${ARTEX_API_BASE}/health`),
        fetchJson(`${ARTEX_API_BASE}/stats`),
        fetchJson(`${ARTEX_API_BASE}/engagements`),
        fetchJson(`${ARTEX_API_BASE}/assets${goFilter}`),
        fetchJson(`${ARTEX_API_BASE}/findings${goFilter}`),
        fetchJson(`${ARTEX_API_BASE}/tasks${goFilter}`),
        fetchJson(`${ARTEX_API_BASE}/audit${goFilter}`),
        fetchJson("/api/platform/overview", true),
        fetchJson("/api/platform/artex/health", true),
        fetchJson("/api/platform/approvals", true),
        fetchJson("/api/platform/runs", true),
      ]);

      if (signal.aborted) return;

      const nowTs = Date.now();

      // 1. Evaluate FastAPI Hub Health
      const hubOv = (hubOverviewRes.data && typeof hubOverviewRes.data === "object"
        ? hubOverviewRes.data
        : null) as Record<string, unknown> | null;

      if (hubOverviewRes.ok && hubOv && hubOv.status === "ok") {
        const latestSeq = Number(hubOv.latest_seq || 0);
        if (latestSeq > lastSeqRef.current) {
          lastSeqRef.current = latestSeq;
          lastEventIdRef.current = String(latestSeq);
        }
        const ctxObj =
          hubOv.context && typeof hubOv.context === "object"
            ? (hubOv.context as Record<string, unknown>)
            : null;
        if (ctxObj) {
          const nextRunId =
            typeof ctxObj.active_run_id === "string" && ctxObj.active_run_id
              ? ctxObj.active_run_id
              : null;
          if (fpRef.current.activeRunId !== (nextRunId || "")) {
            fpRef.current.activeRunId = nextRunId || "";
            setActiveRunId(nextRunId);
          }
        }
        const services = (hubOv.services || {}) as HunterHubHealth["services"];
        const nextHub: HunterHubHealth = {
          status: "connected",
          lastSyncedAt: nowTs,
          latestSeq,
          services,
        };
        const fp = fingerprintData({ s: nextHub.status, services });
        if (fpRef.current.hubHealth !== fp) {
          fpRef.current.hubHealth = fp;
          setHunterHubHealth(nextHub);
        } else {
          setHunterHubHealth((prev) => ({ ...prev, lastSyncedAt: nowTs, latestSeq }));
        }
      } else {
        const errMsg =
          (hubOv && typeof hubOv.error === "string" ? hubOv.error : "") ||
          "FastAPI Platform Hub unreachable";
        const nextHub: HunterHubHealth = {
          status: "offline",
          error: errMsg,
          lastSyncedAt: nowTs,
          latestSeq: lastSeqRef.current,
        };
        const fp = fingerprintData({ s: "offline", errMsg });
        if (fpRef.current.hubHealth !== fp) {
          fpRef.current.hubHealth = fp;
          setHunterHubHealth(nextHub);
        }
      }

      // 2. Evaluate Truthful Go Core Health (Direct + /api/platform/artex/health)
      const directData = (goHealthRes.data && typeof goHealthRes.data === "object"
        ? goHealthRes.data
        : null) as Record<string, unknown> | null;
      const bridgeData = (hubArtexHealthRes.data && typeof hubArtexHealthRes.data === "object"
        ? hubArtexHealthRes.data
        : null) as Record<string, unknown> | null;

      let nextGoHealth: GoCoreHealth;
      if (goHealthRes.status === 200 && directData) {
        nextGoHealth = {
          status: "connected",
          database: directData.database === "connected" ? "connected" : "unknown",
          engine: typeof directData.engine === "string" ? directData.engine : "ARTEX-Pro Go Core",
          lastSyncedAt: nowTs,
          viaBridge: false,
        };
      } else if (goHealthRes.status === 503 && directData) {
        nextGoHealth = {
          status: "degraded",
          database: directData.database === "disconnected" ? "disconnected" : "unknown",
          engine: typeof directData.engine === "string" ? directData.engine : "ARTEX-Pro Go Core",
          error: typeof directData.error === "string" ? directData.error : "Database unavailable",
          lastSyncedAt: nowTs,
          viaBridge: false,
        };
      } else if (hubArtexHealthRes.ok && bridgeData && bridgeData.online === true) {
        nextGoHealth = {
          status: "connected",
          database: "connected",
          engine: "ARTEX-Pro Go Core",
          lastSyncedAt: nowTs,
          viaBridge: true,
        };
      } else if (bridgeData && bridgeData.status === "degraded") {
        nextGoHealth = {
          status: "degraded",
          database: "disconnected",
          error: typeof bridgeData.error === "string" ? bridgeData.error : "Database degraded",
          lastSyncedAt: nowTs,
          viaBridge: true,
        };
      } else {
        nextGoHealth = {
          status: "offline",
          database: "unknown",
          error:
            (bridgeData && typeof bridgeData.error === "string" ? bridgeData.error : "") ||
            "Go Core API unreachable",
          lastSyncedAt: nowTs,
        };
      }

      const goHealthFp = fingerprintData({
        status: nextGoHealth.status,
        database: nextGoHealth.database,
        error: nextGoHealth.error,
        viaBridge: nextGoHealth.viaBridge,
      });
      if (fpRef.current.goHealth !== goHealthFp) {
        fpRef.current.goHealth = goHealthFp;
        setGoCoreHealth(nextGoHealth);
      } else {
        setGoCoreHealth((prev) => ({ ...prev, lastSyncedAt: nowTs }));
      }

      // 3. Stats
      if (goStatsRes.data && typeof goStatsRes.data === "object") {
        const s = goStatsRes.data as Record<string, unknown>;
        const nextStats: StatsSummary = {
          total_assets: Number(s.total_assets || 0),
          total_findings: Number(s.total_findings || 0),
          total_engagements: Number(s.total_engagements || 0),
          status: String(s.status || (goStatsRes.ok ? "ONLINE" : "DEGRADED")),
          error: typeof s.error === "string" ? s.error : undefined,
        };
        const fp = fingerprintData(nextStats);
        if (fpRef.current.stats !== fp) {
          fpRef.current.stats = fp;
          setStats(nextStats);
        }
      } else if (nextGoHealth.status === "offline") {
        const offlineStats: StatsSummary = {
          total_assets: 0,
          total_findings: 0,
          total_engagements: 0,
          status: "OFFLINE",
        };
        const fp = fingerprintData(offlineStats);
        if (fpRef.current.stats !== fp) {
          fpRef.current.stats = fp;
          setStats(offlineStats);
        }
      }

      // 4. Engagements (Merge Go Core + FastAPI Hub)
      const mergedEngs: EngagementRecord[] = [];
      const seenEngIds = new Set<string>();

      if (goEngsRes.ok && Array.isArray(goEngsRes.data)) {
        for (const item of goEngsRes.data) {
          if (!item || typeof item !== "object") continue;
          const ge = item as Record<string, unknown>;
          const id = String(ge.id || ge.code || "");
          if (!id || seenEngIds.has(id)) continue;
          seenEngIds.add(id);
          const rawScope = String(ge.authorized_scope || "");
          mergedEngs.push({
            id,
            name: String(ge.code || ge.target_url || id),
            target: String(ge.target_url || "").replace(/^https?:\/\//, ""),
            code: typeof ge.code === "string" ? ge.code : undefined,
            in_scope: rawScope
              .split(",")
              .map((s) => s.trim())
              .filter(Boolean),
            out_of_scope: [],
            status: String(ge.status || "ACTIVE").toLowerCase(),
            source: "artex_go",
            isGoUuid: UUID_RE.test(id),
            created_at: typeof ge.created_at === "string" ? ge.created_at : null,
          });
        }
      }

      if (hubOverviewRes.ok && hubOv && Array.isArray(hubOv.engagements)) {
        for (const item of hubOv.engagements) {
          if (!item || typeof item !== "object") continue;
          const he = item as Record<string, unknown>;
          const id = String(he.engagement_id || he.id || "");
          if (!id || seenEngIds.has(id)) continue;
          seenEngIds.add(id);
          mergedEngs.push({
            id,
            name: String(he.name || he.target || id),
            target: String(he.target || "").replace(/^https?:\/\//, ""),
            in_scope: Array.isArray(he.in_scope) ? he.in_scope.map(String) : [],
            out_of_scope: Array.isArray(he.out_of_scope) ? he.out_of_scope.map(String) : [],
            status: String(he.status || "authorized").toLowerCase(),
            source: String(he.source || "local"),
            isGoUuid: UUID_RE.test(id),
            created_at: he.created_at ? String(he.created_at) : null,
          });
        }
      }

      const engFp = fingerprintData(mergedEngs);
      if (fpRef.current.engagements !== engFp) {
        fpRef.current.engagements = engFp;
        setEngagements(mergedEngs);
      }

      // 5. Assets
      if (goAssetsRes.ok && Array.isArray(goAssetsRes.data)) {
        const normalizedAssets: AssetRecord[] = goAssetsRes.data
          .filter((a): a is Record<string, unknown> => Boolean(a && typeof a === "object"))
          .map((a) => ({
            id: String(a.id || ""),
            target_id: typeof a.target_id === "string" ? a.target_id : undefined,
            kind: String(a.kind || "ASSET"),
            value: String(a.value || ""),
            attributes:
              a.attributes && typeof a.attributes === "object"
                ? (a.attributes as Record<string, unknown>)
                : {},
            first_seen: typeof a.first_seen === "string" ? a.first_seen : null,
            created_at: typeof a.created_at === "string" ? a.created_at : null,
          }));
        const fp = fingerprintData(normalizedAssets);
        if (fpRef.current.assets !== fp) {
          fpRef.current.assets = fp;
          setAssets(normalizedAssets);
        }
      }

      // 6. Findings
      if (goFindingsRes.ok && Array.isArray(goFindingsRes.data)) {
        const normalizedFindings: FindingRecord[] = goFindingsRes.data
          .filter((f): f is Record<string, unknown> => Boolean(f && typeof f === "object"))
          .map((f) => ({
            id: String(f.id || ""),
            engagement_id: typeof f.engagement_id === "string" ? f.engagement_id : undefined,
            target_id: typeof f.target_id === "string" ? f.target_id : undefined,
            title: String(f.title || "Untitled Finding"),
            vuln_class: String(f.vuln_class || "unknown"),
            severity: String(f.severity || "info").toUpperCase(),
            cvss_score: Number(f.cvss_score || 0),
            confidence: Number(f.confidence || 0),
            endpoint: String(f.endpoint || ""),
            evidence: String(f.evidence || ""),
            poc_details:
              f.poc_details && typeof f.poc_details === "object"
                ? (f.poc_details as Record<string, unknown>)
                : undefined,
            poc_script: typeof f.poc_script === "string" ? f.poc_script : undefined,
            status: String(f.status || "CONFIRMED"),
            created_at: typeof f.created_at === "string" ? f.created_at : null,
          }));
        const fp = fingerprintData(normalizedFindings);
        if (fpRef.current.findings !== fp) {
          fpRef.current.findings = fp;
          setFindings(normalizedFindings);
        }
      }

      // 7. Go Tasks
      if (goTasksRes.ok && Array.isArray(goTasksRes.data)) {
        const normalizedTasks: TaskRecord[] = goTasksRes.data
          .filter((t): t is Record<string, unknown> => Boolean(t && typeof t === "object"))
          .map((t) => ({
            id: String(t.id || ""),
            engagement_id: typeof t.engagement_id === "string" ? t.engagement_id : undefined,
            agent_role: String(t.agent_role || "WORKER"),
            title: String(t.title || ""),
            status: String(t.status || "PENDING"),
            priority: Number(t.priority || 5),
            input_context:
              t.input_context && typeof t.input_context === "object"
                ? (t.input_context as Record<string, unknown>)
                : {},
            output_summary:
              t.output_summary && typeof t.output_summary === "object"
                ? (t.output_summary as Record<string, unknown>)
                : {},
            created_at: typeof t.created_at === "string" ? t.created_at : null,
            updated_at: typeof t.updated_at === "string" ? t.updated_at : null,
          }));
        const fp = fingerprintData(normalizedTasks);
        if (fpRef.current.tasks !== fp) {
          fpRef.current.tasks = fp;
          setTasks(normalizedTasks);
        }
      }

      // 8. Go Audit Logs (append new records into LiveConsole unless paused)
      if (goAuditRes.ok && Array.isArray(goAuditRes.data)) {
        const normalizedAudit: AuditRecord[] = goAuditRes.data
          .filter((a): a is Record<string, unknown> => Boolean(a && typeof a === "object"))
          .map((a) => ({
            id: String(a.id || ""),
            engagement_id: typeof a.engagement_id === "string" ? a.engagement_id : undefined,
            actor: String(a.actor || "system"),
            action: String(a.action || ""),
            details:
              a.details && typeof a.details === "object"
                ? (a.details as Record<string, unknown>)
                : {},
            created_at: typeof a.created_at === "string" ? a.created_at : null,
          }));
        const fp = fingerprintData(normalizedAudit);
        if (fpRef.current.audit !== fp) {
          fpRef.current.audit = fp;
          setAuditLogs(normalizedAudit);
          if (!streamPausedRef.current) {
            const reversed = [...normalizedAudit].reverse();
            for (const entry of reversed) {
              if (!entry.id || seenAuditIdsRef.current.has(entry.id)) continue;
              seenAuditIdsRef.current.add(entry.id);
              const detailText =
                Object.keys(entry.details).length > 0 ? ` ${JSON.stringify(entry.details)}` : "";
              addConsoleLog(
                "AUDIT",
                entry.actor,
                `${entry.action}${detailText}`,
                `audit:${entry.id}`,
                formatTimeHHMMSS(entry.created_at)
              );
            }
          }
        }
      }

      // 9. FastAPI Runs & Approvals
      const runsPayload = hubRunsRes.data as { runs?: unknown[] } | null;
      const rawRuns =
        hubRunsRes.ok && runsPayload && Array.isArray(runsPayload.runs)
          ? runsPayload.runs
          : hubOverviewRes.ok && hubOv && Array.isArray(hubOv.runs)
            ? hubOv.runs
            : null;
      if (rawRuns) {
        const normalizedRuns = rawRuns.filter(
          (r): r is RunRecord => Boolean(r && typeof r === "object" && "run_id" in r)
        );
        const fp = fingerprintData(normalizedRuns);
        if (fpRef.current.runs !== fp) {
          fpRef.current.runs = fp;
          setRuns(normalizedRuns);
        }
      }

      const approvalsPayload = hubApprovalsRes.data as { approvals?: unknown[] } | null;
      const rawApprovals =
        hubApprovalsRes.ok && approvalsPayload && Array.isArray(approvalsPayload.approvals)
          ? approvalsPayload.approvals
          : null;
      if (rawApprovals) {
        const normalizedApprovals = rawApprovals.filter(
          (a): a is ApprovalRecord => Boolean(a && typeof a === "object" && "approval_id" in a)
        );
        const fp = fingerprintData(normalizedApprovals);
        if (fpRef.current.approvals !== fp) {
          fpRef.current.approvals = fp;
          setApprovals(normalizedApprovals);
        }
      }
    } finally {
      if (!signal.aborted) {
        setIsLoading(false);
      }
    }
  }, [addConsoleLog, hunterFetch]);

  // Visibility-aware polling loop (4s interval, paused when document.hidden === true)
  useEffect(() => {
    void refreshData();

    const timer = window.setInterval(() => {
      if (!document.hidden) {
        void refreshData();
      }
    }, 4000);

    const onVisibilityChange = () => {
      if (document.hidden) {
        if (pollAbortRef.current) {
          pollAbortRef.current.abort();
        }
      } else {
        void refreshData();
      }
    };

    document.addEventListener("visibilitychange", onVisibilityChange);
    return () => {
      window.clearInterval(timer);
      document.removeEventListener("visibilitychange", onVisibilityChange);
      if (pollAbortRef.current) {
        pollAbortRef.current.abort();
      }
    };
  }, [refreshData]);

  // SSE /api/platform/stream subscription when FastAPI Hub is reachable and page is visible
  useEffect(() => {
    if (hunterHubHealth.status !== "connected") {
      return;
    }

    let cancelled = false;
    let activeController: AbortController | null = null;
    let reconnectTimer: number | null = null;
    let backoffMs = 2000;

    const connectSse = async () => {
      if (cancelled || (typeof document !== "undefined" && document.hidden)) {
        return;
      }
      activeController = new AbortController();
      const currentSeq = lastSeqRef.current;
      const since = currentSeq > 0 ? `?since_seq=${encodeURIComponent(currentSeq)}` : "";
      const lastEventIdHeader = currentSeq > 0 ? String(currentSeq) : lastEventIdRef.current;
      const headers: Record<string, string> = {
        Accept: "text/event-stream",
      };
      if (lastEventIdHeader) {
        headers["Last-Event-ID"] = lastEventIdHeader;
      }

      try {
        const resp = await hunterFetch(`/api/platform/stream${since}`, {
          headers,
          signal: activeController.signal,
        });
        if (!resp.ok || !resp.body) {
          throw new Error(`SSE HTTP ${resp.status}`);
        }
        backoffMs = 2000;

        const reader = resp.body.getReader();
        const decoder = new TextDecoder("utf-8");
        let buffer = "";

        const dispatchBlock = (block: string) => {
          const lines = block.split(/\r?\n/);
          let eventName = "message";
          let eventId = "";
          const dataLines: string[] = [];
          for (const line of lines) {
            if (!line || line.startsWith(":")) continue;
            if (line.startsWith("event:")) {
              eventName = line.slice(6).trim() || "message";
            } else if (line.startsWith("id:")) {
              eventId = line.slice(3).trim();
            } else if (line.startsWith("data:")) {
              dataLines.push(line.slice(5).trimStart());
            }
          }

          let parsedId = 0;
          if (eventId && !eventId.includes("\0")) {
            lastEventIdRef.current = eventId;
            if (/^\d+$/.test(eventId)) {
              parsedId = Number.parseInt(eventId, 10);
              if (parsedId > lastSeqRef.current) {
                lastSeqRef.current = parsedId;
                setHunterHubHealth((prev) =>
                  parsedId > prev.latestSeq ? { ...prev, latestSeq: parsedId } : prev
                );
              }
            }
          }

          if (dataLines.length === 0) return;
          try {
            const ev = JSON.parse(dataLines.join("\n")) as Record<string, unknown>;
            const rawSeq = Number(ev.seq ?? parsedId ?? 0);
            const seq = Number.isFinite(rawSeq) && rawSeq > 0 ? rawSeq : 0;
            if (seq > lastSeqRef.current) {
              lastSeqRef.current = seq;
              lastEventIdRef.current = String(seq);
              setHunterHubHealth((prev) =>
                seq > prev.latestSeq ? { ...prev, latestSeq: seq } : prev
              );
            }
            if (seq && seenSseSeqRef.current.has(seq)) {
              return;
            }
            if (seq) {
              seenSseSeqRef.current.add(seq);
            }

            if (!streamPausedRef.current) {
              const evType = String(ev.event_type || eventName).toUpperCase();
              const source = String(ev.source || "platform_hub");
              const payload = ev.payload ? JSON.stringify(ev.payload) : "";
              const level: ConsoleLevel = evType.includes("FAIL") || evType.includes("ERROR")
                ? "ERROR"
                : evType.includes("COMPLETED") || evType.includes("APPROVED") || evType.includes("STARTED")
                  ? "SUCCESS"
                  : evType.includes("STOP") || evType.includes("REJECT") || evType.includes("BLOCK")
                    ? "WARN"
                    : "INFO";
              addConsoleLog(
                level,
                source,
                `${evType}${payload && payload !== "{}" ? ` ${payload}` : ""}`,
                seq ? `sse:${seq}` : undefined,
                formatTimeHHMMSS(typeof ev.created_at === "number" ? ev.created_at : null)
              );
            }

            if (
              eventName.startsWith("RUN_") ||
              eventName.startsWith("APPROVAL_") ||
              eventName === "ENGAGEMENT_CREATED"
            ) {
              void refreshData();
            }
          } catch {
            // Ignore malformed SSE payload
          }
        };

        const flushCompleteBlocks = () => {
          let idx: number;
          while ((idx = buffer.search(/\r?\n\r?\n/)) !== -1) {
            const sepLen = buffer.slice(idx).startsWith("\r\n\r\n") ? 4 : 2;
            const block = buffer.slice(0, idx);
            buffer = buffer.slice(idx + sepLen);
            dispatchBlock(block);
          }
        };

        while (!cancelled) {
          const { value, done } = await reader.read();
          if (done) {
            buffer += decoder.decode();
            break;
          }
          buffer += decoder.decode(value, { stream: true });
          flushCompleteBlocks();
        }
        if (!cancelled) {
          flushCompleteBlocks();
          if (buffer.trim()) {
            dispatchBlock(buffer);
            buffer = "";
          }
        }
      } catch {
        // Ignore aborts; schedule backoff reconnect below
      }

      if (!cancelled && (typeof document === "undefined" || !document.hidden)) {
        reconnectTimer = window.setTimeout(() => {
          backoffMs = Math.min(backoffMs * 2, 15000);
          void connectSse();
        }, backoffMs);
      }
    };

    const onVisibility = () => {
      if (document.hidden) {
        if (activeController) activeController.abort();
        if (reconnectTimer !== null) window.clearTimeout(reconnectTimer);
      } else {
        void connectSse();
      }
    };

    document.addEventListener("visibilitychange", onVisibility);
    void connectSse();

    return () => {
      cancelled = true;
      document.removeEventListener("visibilitychange", onVisibility);
      if (activeController) activeController.abort();
      if (reconnectTimer !== null) window.clearTimeout(reconnectTimer);
    };
  }, [hunterHubHealth.status, hunterFetch, addConsoleLog, refreshData]);

  const selectedEngagement = useMemo(
    () => engagements.find((e) => e.id === selectedEngagementId) || null,
    [engagements, selectedEngagementId]
  );

  const selectEngagement = useCallback(
    async (id: string) => {
      setSelectedEngagementId(id);
      selectedEngRef.current = id;
      const found = engagements.find((e) => e.id === id);
      if (found && found.target) {
        setTargetDomain(found.target);
      }
      if (hunterHubHealth.status === "connected" && id) {
        try {
          await hunterFetch("/api/platform/context", {
            method: "PUT",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ active_engagement_id: id }),
          });
        } catch {
          // Non-fatal
        }
      }
      await refreshData();
    },
    [engagements, hunterHubHealth.status, hunterFetch, refreshData]
  );

  const launchScan = useCallback(
    async (rawTarget: string): Promise<{ ok: boolean; error?: string; via?: string }> => {
      const check = validateScanTarget(rawTarget, selectedEngagement);
      if (!check.valid) {
        return { ok: false, error: check.reason || "invalid_format" };
      }

      setTargetDomain(check.normalizedTarget);
      setIsScanning(true);
      addConsoleLog("INFO", "dispatcher", `Dispatching autonomous scan for target: ${check.normalizedTarget}`);

      try {
        const res = await fetch(`${ARTEX_API_BASE}/scan`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ target: check.normalizedTarget }),
        });

        if (res.ok) {
          addConsoleLog(
            "SUCCESS",
            "go-core",
            `Scan accepted by ARTEX-Pro Go Core (${res.status}) for ${check.normalizedTarget}`
          );
          void refreshData();
          return { ok: true, via: "go_core" };
        }

        const errData = (await res.json().catch(() => null)) as { error?: string } | null;
        const errMsg = errData?.error || `Go Core returned HTTP ${res.status}`;
        addConsoleLog("ERROR", "go-core", `Scan dispatch rejected: ${errMsg}`);
        return { ok: false, error: errMsg };
      } catch (err) {
        const msg = err instanceof Error ? err.message : "Go Core API unreachable";
        addConsoleLog("ERROR", "go-core", `Failed to reach Go Core API: ${msg}`);
        return { ok: false, error: msg };
      } finally {
        window.setTimeout(() => setIsScanning(false), 1200);
      }
    },
    [selectedEngagement, addConsoleLog, refreshData]
  );

  const decideApproval = useCallback(
    async (
      approvalId: string,
      decision: "approved" | "rejected",
      note = ""
    ): Promise<{ ok: boolean; error?: string }> => {
      try {
        const res = await hunterFetch(`/api/platform/approvals/${encodeURIComponent(approvalId)}/decide`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ decision, note, decided_by: "artex-nextjs-operator" }),
        });
        const data = (await res.json().catch(() => null)) as { detail?: unknown; error?: string } | null;
        if (!res.ok) {
          const detail =
            typeof data?.detail === "string"
              ? data.detail
              : data?.error || `HTTP ${res.status}`;
          addConsoleLog("ERROR", "approvals", `Approval decision failed (${approvalId}): ${detail}`);
          return { ok: false, error: detail };
        }
        addConsoleLog(
          decision === "approved" ? "SUCCESS" : "WARN",
          "approvals",
          `Approval ${approvalId} marked ${decision}`
        );
        await refreshData();
        return { ok: true };
      } catch (err) {
        const msg = err instanceof Error ? err.message : "Request failed";
        return { ok: false, error: msg };
      }
    },
    [hunterFetch, addConsoleLog, refreshData]
  );

  const controlRun = useCallback(
    async (
      runId: string,
      action: "pause" | "resume" | "stop"
    ): Promise<{ ok: boolean; error?: string }> => {
      try {
        const res = await hunterFetch(`/api/platform/runs/${encodeURIComponent(runId)}/${action}`, {
          method: "POST",
        });
        if (!res.ok) {
          return { ok: false, error: `HTTP ${res.status}` };
        }
        addConsoleLog("INFO", "runs", `Run ${runId} -> ${action}`);
        await refreshData();
        return { ok: true };
      } catch (err) {
        return { ok: false, error: err instanceof Error ? err.message : "Failed" };
      }
    },
    [hunterFetch, addConsoleLog, refreshData]
  );

  const navigateToRef = useCallback(
    (ref: CopilotRef): boolean => {
      const kind = (ref.kind || "").toLowerCase();
      if (kind === "asset") {
        const match =
          assets.find((a) => a.id === ref.id) ||
          assets.find((a) => ref.label && ref.label.includes(a.value));
        if (match) {
          setInspectedAsset(match);
          return true;
        }
        return false;
      }
      if (kind === "finding") {
        const match =
          findings.find((f) => f.id === ref.id) ||
          findings.find((f) => ref.label && ref.label.includes(f.title));
        if (match) {
          setInspectedFinding(match);
          return true;
        }
        return false;
      }
      if (kind === "approval") {
        const el = document.getElementById("approvals-panel");
        el?.scrollIntoView({ behavior: "smooth", block: "nearest" });
        return Boolean(el);
      }
      if (kind === "engagement" && ref.id) {
        void selectEngagement(ref.id);
        return true;
      }
      return false;
    },
    [assets, findings, selectEngagement]
  );

  const pendingApprovalsCount = useMemo(
    () => approvals.filter((a) => a.status === "pending").length,
    [approvals]
  );

  const value = useMemo<PlatformContextValue>(
    () => ({
      engagements,
      selectedEngagementId,
      selectedEngagement,
      selectEngagement,
      targetDomain,
      setTargetDomain,
      stats,
      assets,
      findings,
      tasks,
      auditLogs,
      runs,
      activeRunId,
      approvals,
      pendingApprovalsCount,
      goCoreHealth,
      hunterHubHealth,
      isLoading,
      isScanning,
      streamPaused,
      setStreamPaused,
      consoleLogs,
      addConsoleLog,
      clearConsoleLogs,
      refreshNow: refreshData,
      launchScan,
      decideApproval,
      controlRun,
      inspectedAsset,
      setInspectedAsset,
      inspectedFinding,
      setInspectedFinding,
      copilotOpen,
      setCopilotOpen,
      navigateToRef,
      hunterFetch,
    }),
    [
      engagements,
      selectedEngagementId,
      selectedEngagement,
      selectEngagement,
      targetDomain,
      stats,
      assets,
      findings,
      tasks,
      auditLogs,
      runs,
      activeRunId,
      approvals,
      pendingApprovalsCount,
      goCoreHealth,
      hunterHubHealth,
      isLoading,
      isScanning,
      streamPaused,
      consoleLogs,
      addConsoleLog,
      clearConsoleLogs,
      refreshData,
      launchScan,
      decideApproval,
      controlRun,
      inspectedAsset,
      inspectedFinding,
      copilotOpen,
      navigateToRef,
      hunterFetch,
    ]
  );

  return <PlatformContext.Provider value={value}>{children}</PlatformContext.Provider>;
}

export function usePlatform(): PlatformContextValue {
  const ctx = useContext(PlatformContext);
  if (!ctx) {
    throw new Error("usePlatform must be used within PlatformProvider");
  }
  return ctx;
}
