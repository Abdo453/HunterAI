/**
 * Canonical TypeScript API contracts for the ARTEX-Pro / HunterAI Unified Platform.
 * Aligned with hunter_backend/apps/{platform_api,arsenal_api,operations_api,intelligence_api,copilot_api}.py.
 */

export type ServiceConnectivity = "connected" | "degraded" | "offline" | "checking";

export type StreamConnectionState = "live" | "connecting" | "reconnecting" | "offline";

export type AuthStatus = "authenticated" | "auth_required" | "forbidden" | "checking";

export type CourtVerdictState =
  | "UNVERIFIED"
  | "CANDIDATE"
  | "CONFIRMED"
  | "REJECTED"
  | "INCONCLUSIVE"
  | "UNAVAILABLE"
  | "ERROR";

export const COURT_VERDICT_STATES: readonly CourtVerdictState[] = [
  "UNVERIFIED",
  "CANDIDATE",
  "CONFIRMED",
  "REJECTED",
  "INCONCLUSIVE",
  "UNAVAILABLE",
  "ERROR",
] as const;

export function normalizeRunProgressPercent(progress?: number | null): number {
  if (typeof progress !== "number" || !Number.isFinite(progress)) return 0;
  if (progress <= 0) return 0;
  if (progress <= 1) return Math.round(progress * 100);
  return Math.round(Math.min(100, progress));
}

export function normalizeCourtVerdict(raw?: string | null): CourtVerdictState {
  const upper = String(raw || "").trim().toUpperCase();
  if (upper === "CONFIRMED" || upper === "VERIFIED" || upper === "E3_CONFIRMED") return "CONFIRMED";
  if (upper === "CANDIDATE" || upper === "SUSPECTED" || upper === "TRIAGED" || upper === "PENDING") return "CANDIDATE";
  if (upper === "REJECTED" || upper === "FALSE_POSITIVE" || upper === "CONTRADICTED" || upper === "DENIED") return "REJECTED";
  if (upper === "INCONCLUSIVE" || upper === "PARTIAL") return "INCONCLUSIVE";
  if (upper === "UNAVAILABLE" || upper === "BLOCKED") return "UNAVAILABLE";
  if (upper === "ERROR" || upper === "FAILED") return "ERROR";
  return "UNVERIFIED";
}

export interface AssetRecord {
  id: string;
  target_id?: string;
  engagement_id?: string;
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
  run_id?: string;
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
  verdict?: CourtVerdictState;
  created_at?: string | null;
}

export interface SubtaskNode {
  subtask_id: string;
  task_id: string;
  run_id?: string;
  title: string;
  description?: string;
  status: string;
  result?: string;
  agent_role?: string;
  created_at?: number | string | null;
  updated_at?: number | string | null;
}

export interface TaskNode {
  task_id: string;
  run_id?: string;
  engagement_id?: string;
  title: string;
  role: string;
  status: string;
  priority?: number;
  summary?: string;
  subtasks: SubtaskNode[];
  input_context?: Record<string, unknown>;
  output_summary?: Record<string, unknown>;
  created_at?: number | string | null;
  updated_at?: number | string | null;
}

export interface TaskRecord {
  id: string;
  engagement_id?: string;
  run_id?: string;
  agent_role: string;
  title: string;
  status: string;
  priority: number;
  input_context: Record<string, unknown>;
  output_summary: Record<string, unknown>;
  subtasks?: SubtaskNode[];
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

export interface MissionRun {
  run_id: string;
  kind: string;
  target: string;
  engagement_id?: string | null;
  status: string;
  canonical_status?: string;
  current_phase?: string;
  progress?: number;
  error?: string;
  started_at?: number | null;
  finished_at?: number | null;
  created_at?: number | null;
  updated_at?: number | null;
  checkpoint_id?: string | null;
  recoverable?: boolean;
  meta?: Record<string, unknown>;
}

export type RunRecord = MissionRun;

export interface ApprovalExecutionResult {
  executed: boolean;
  blocked: boolean;
  returncode?: number | null;
  stdout_excerpt?: string;
  stderr_excerpt?: string;
  error?: string | null;
  action_type?: string;
  target?: string;
  approval_id?: string;
}

export interface ApprovalItem {
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
  proposal_digest?: string;
  decision_note?: string;
  decided_by?: string;
  decided_at?: number | null;
  created_at: number;
  payload?: Record<string, unknown>;
  execution?: ApprovalExecutionResult | null;
}

export type ApprovalRecord = ApprovalItem;

export interface NotificationItem {
  notification_id: string;
  level?: string;
  title?: string;
  message: string;
  source?: string;
  engagement_id?: string | null;
  run_id?: string | null;
  read: boolean;
  created_at: number;
  payload?: Record<string, unknown>;
}

export interface PlatformOverview {
  status: string;
  latest_seq: number;
  context?: {
    active_engagement_id?: string | null;
    active_run_id?: string | null;
    active_conversation_id?: string | null;
    extra?: Record<string, unknown>;
  };
  engagements?: Array<Record<string, unknown>>;
  runs?: MissionRun[];
  assets?: Array<Record<string, unknown>>;
  findings?: Array<Record<string, unknown>>;
  pending_approvals?: ApprovalItem[];
  unread_notifications?: NotificationItem[];
  recent_events?: Array<Record<string, unknown>>;
  services?: HubServicesSnapshot;
  counts?: OverviewCounts;
  artex?: Record<string, unknown>;
  stats?: Record<string, unknown>;
}

export interface StatsSummary {
  total_assets: number;
  total_findings: number;
  total_engagements: number;
  status: string;
  error?: string;
}

export interface GoCoreHealth {
  status: ServiceConnectivity;
  database: "connected" | "disconnected" | "unknown";
  engine?: string;
  error?: string;
  lastSyncedAt: number | null;
  viaBridge?: boolean;
}

export interface HubServicesSnapshot {
  artex_go_core?: Record<string, unknown>;
  ollama?: { online: boolean; host?: string };
  lm_studio?: { online: boolean; host?: string };
  cloud_providers?: string[];
  burp_proxy?: { online: boolean; host?: string };
  burp_agent?: { online: boolean; host?: string };
}

export interface HunterHubHealth {
  status: "connected" | "offline" | "checking";
  error?: string;
  lastSyncedAt: number | null;
  latestSeq: number;
  services?: HubServicesSnapshot;
}

export interface OverviewCounts {
  engagements: number;
  runs: number;
  active_runs: number;
  pending_approvals: number;
  findings: number;
  assets: number;
  leads: number;
  conversations: number;
  unread_notifications: number;
  tools_installed: number;
  agents: number;
}

export interface GpuDeviceTelemetry {
  index: number;
  name: string;
  vram_total_mb: number;
  vram_used_mb: number;
  vram_free_mb: number;
  vram_used_pct: number;
  utilization_pct: number | null;
}

export interface OllamaLoadedModel {
  name: string;
  size_mb: number;
  size_vram_mb: number;
  expires_at?: string | null;
}

export interface HardwareTelemetry {
  timestamp?: number;
  platform?: {
    system?: string;
    release?: string;
    machine?: string;
  };
  cpu: {
    status: string;
    percent: number | null;
    logical_cores?: number | null;
    physical_cores?: number | null;
    detail?: string;
  };
  ram: {
    status: string;
    total_mb: number | null;
    used_mb: number | null;
    available_mb: number | null;
    percent: number | null;
    detail?: string;
  };
  gpu: {
    status: "available" | "unavailable" | string;
    available: boolean;
    source: string;
    count: number;
    gpus: GpuDeviceTelemetry[];
    vram_total_mb: number;
    vram_used_mb: number;
    vram_free_mb: number;
    vram_used_pct: number;
  };
  ollama: {
    status: string;
    host?: string;
    loaded_models: OllamaLoadedModel[];
    count?: number;
    detail?: string;
  };
  vram_manager?: {
    currently_loaded_model?: string | null;
  };
  gpu_scheduler?: Record<string, unknown>;
  hardware_profile?: {
    configured?: string;
    active?: string;
    default_num_ctx?: number;
    keep_alive_seconds?: number;
    prefer_cloud_fallback?: boolean;
    role_models?: Record<string, string>;
  };
}

export interface BudgetBreakdownEntry {
  usd: number;
  input_tokens?: number;
  output_tokens?: number;
  tokens?: number;
  calls?: number;
}

export interface BudgetSummary {
  global_usd?: number;
  global_tokens?: number;
  input_tokens?: number;
  output_tokens?: number;
  calls?: number;
  unpriced_calls?: number;
  today_usd?: number;
  total_usd?: number;
  source?: string;
  budget?: {
    per_run_usd?: number | null;
    per_solver_usd?: number | null;
    per_day_usd?: number | null;
  };
  spent?: {
    today_usd?: number;
    total_usd?: number;
  };
  by_run?: Record<string, BudgetBreakdownEntry | number>;
  by_solver?: Record<string, BudgetBreakdownEntry | number>;
  by_provider?: Record<string, BudgetBreakdownEntry | number>;
  by_model?: Record<string, BudgetBreakdownEntry | number>;
  by_role?: Record<string, BudgetBreakdownEntry | number>;
  per_run_usd?: number | null;
  per_solver_usd?: number | null;
  per_day_usd?: number | null;
}

export interface EvidenceVerdict {
  court_id?: string;
  run_id?: string;
  finding_id?: string;
  evidence_id?: string;
  title: string;
  endpoint?: string;
  vuln_class?: string;
  verdict: CourtVerdictState;
  reason_code?: string;
  rationale?: string;
  confidence?: number;
  evidence?: string;
  proof_strength?: string;
  decided_at?: string | number | null;
  provenance?: Record<string, unknown> | string;
}

export interface EvidenceLedgerResponse {
  counts?: Record<string, number>;
  runs?: string[];
  recent?: Record<string, Array<Record<string, unknown>>>;
}

export interface VulnIntelRecord {
  id: string;
  source?: string;
  source_id?: string;
  title?: string;
  summary?: string;
  description?: string;
  severity?: string;
  cvss_score?: number | null;
  cwe?: string | string[];
  cwes?: string[];
  ecosystem?: string;
  vendor?: string;
  product?: string;
  package?: string;
  published_at?: string;
  published?: string;
  references?: string[];
  affected?: Array<Record<string, unknown>>;
}

export interface VulnIntelSearchResponse {
  ok: boolean;
  status: string;
  source: string;
  total_in_db: number;
  count: number;
  results: VulnIntelRecord[];
}

export interface VulnIntelCoverageResponse {
  ok: boolean;
  source_id?: string;
  stored_count?: number;
  expected_total?: number | null;
  coverage_pct?: number | null;
  completeness?: string;
  window_start?: string;
  window_end?: string;
  gaps?: Array<Record<string, unknown>>;
  db_stats?: Record<string, unknown>;
}

export interface VulnIntelTriageItem {
  vuln_id?: string;
  id?: string;
  verdict?: string;
  applicable?: boolean | null;
  status?: string;
  reason?: string;
  confidence?: number;
  package?: string;
  matched_version?: string;
}

export interface VulnIntelTriageResponse {
  ok: boolean;
  status: string;
  project_id: string;
  count: number;
  missing_ids: string[];
  results: VulnIntelTriageItem[];
  tool_selections?: Array<Record<string, unknown>>;
}

export interface VulnIntelSyncResponse {
  ok: boolean;
  status?: string;
  source?: string;
  db_path?: string;
  schema_version?: number;
  stored_count?: number;
  stats?: Record<string, unknown>;
  db_stats?: Record<string, unknown>;
  sources?: Array<Record<string, unknown>>;
  report?: Record<string, unknown>;
  error?: string;
}

export interface CopilotRef {
  kind: string;
  id: string;
  label?: string;
  section?: string;
  path?: string;
}

export interface CopilotCitation {
  kind: string;
  id: string;
  label: string;
  excerpt?: string;
}

export interface CopilotEvent {
  event:
    | "start"
    | "context"
    | "citations"
    | "approval_request"
    | "approval_required"
    | "policy_blocked"
    | "thinking"
    | "token"
    | "refs"
    | "done"
    | "error"
    | "message";
  payload: Record<string, unknown>;
}

export interface ModelChoiceItem {
  id: string;
  label: string;
  kind?: "local" | "cloud" | string;
  provider?: string;
  model?: string;
  available?: boolean;
  supports_tools?: boolean;
  supports_thinking?: boolean;
  context_window?: number;
}

export interface ModelCatalogResponse {
  policy?: string;
  ollama_host?: string;
  cloud_available?: boolean;
  local_available?: boolean;
  choices?: ModelChoiceItem[];
  local?: { available?: boolean; models?: string[] };
  cloud?: Array<{
    provider?: string;
    label?: string;
    default_model?: string;
    models?: string[];
  }>;
  roles?: Record<string, Record<string, unknown>>;
}

export interface McpServerRecord {
  server_id: string;
  name: string;
  transport: string;
  command?: string | null;
  args?: string[];
  endpoint?: string | null;
  enabled: boolean;
  fingerprint?: string;
}

export interface BurpStatusResponse {
  online?: boolean;
  proxy?: {
    host?: string;
    port?: number;
    reachable?: boolean;
    online?: boolean;
    status?: string;
    label?: string;
  };
  agent?: {
    host?: string;
    port?: number;
    reachable?: boolean;
    online?: boolean;
    status?: string;
    label?: string;
  };
  stats?: Record<string, unknown>;
  gateway?: Record<string, unknown>;
}

export interface BurpTrafficItem {
  id: string;
  tx_id?: string;
  time: string;
  timestamp?: number;
  method: string;
  host: string;
  path: string;
  url?: string;
  scheme?: string;
  status: number;
  response_status?: number;
  length: number;
  tool_source?: string;
  request_headers?: Record<string, unknown>;
  response_headers?: Record<string, unknown>;
  request_body_preview?: string;
  response_body_preview?: string;
}

export interface BrowserStatusResponse {
  playwright_available?: boolean;
  status?: string;
  connection_status?: string;
  browser_type?: string;
  chrome_binary?: string;
}

export interface SevenGateEvaluation {
  ok?: boolean;
  passed: boolean;
  score: number;
  canonical_verdict?: CourtVerdictState | string;
  proof_strength?: string;
  missing_items?: string[];
  triage_statement?: string;
  answers?: Record<string, unknown>;
  vrt_entry?: unknown;
  evaluation?: Record<string, unknown>;
}

export interface EditorTreeItem {
  type: "directory" | "dir" | "file" | string;
  is_dir?: boolean;
  name: string;
  path: string;
  ext?: string;
  parent?: string | null;
}

export interface StaticAuditResponse {
  ok: boolean;
  findings?: Array<Record<string, unknown>>;
  issues?: Array<Record<string, unknown>>;
  summary?: string;
  result?: unknown;
  error?: string;
}
