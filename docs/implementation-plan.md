# Implementation Plan — Multi-Agent Security Automation Platform

**Repository:** `E:\Agant\PentestAI-Unified`
**Reference Architecture:** Inspired by Muteki (publicly documented architecture) — implemented with original MIT-licensed code, no copying from AGPL.
**Starting State:** The seven agent systems are already embedded with passing tests (see `docs/architecture-audit.md`).
**Implementation Principle:** Strictly additive — no working existing code is deleted or replaced.

---

## Phases and Scope

### Phase A — Audit and Baseline (Complete)

| Item | Status | File |
|---|---|---|
| Repository and architecture audit | ✅ | `docs/architecture-audit.md` |
| Baseline test capture (1709 collected) | ✅ | pytest output in session |
| This implementation plan | ✅ | This file |

### Phase B — Shared Interfaces + Configuration + Tool Registry + Permission Policy (Next)

**Objectives:**
- Unified `AgentProvider` interface for LLM providers (`capabilities` / `health_check` / `execute` / `stream` / `cancel`).
- Composite tool registry (`ToolRegistry`) with structured tool definitions (schema, authorization, risk, timeout, output limit).
- Central permission policy checked before any tool execution.

| Capability | Existing Reuse | Files to Create/Modify | Dependencies | Security Implications | Tests | Acceptance Criteria |
|---|---|---|---|---|---|---|
| LLM provider interface | `core/llm_router.py` exists (model routing) | `core/agent_provider.py` (interface + adapters) | Existing SDKs (no new proprietary protocols) | No secrets in logs | Interface tests + stub providers | `health_check` responds, `execute` returns shared format, `cancel` aborts |
| Composite tool registry | `tools/tool_manager.py` exists (used by `base_agent`) | `core/tool_registry.py` (`Tool` describe/validate_input/authorize/execute/cancel/health_check) | Pydantic for schema validation | Reject unknown tools, validate schemas | Registry, validation, and authorization tests | Unknown tools rejected; invalid arguments rejected |
| Permission policy | `core/scope_guard.py` partially used by `engines_api` | `core/permission_policy.py` (worker, scope, and risk checks) | No new dependencies | Fail-closed: any failed check = deny | Permission, scope bypass, high-risk tool tests | No tool executes without explicit authorization |

### Phase C — Task Coordinator + Worker Registry + Lifecycle + Cancellation

**Objectives:**
- Coordinator accepts a task with explicit scope and creates a task record with a unique run ID.
- Task states: `PENDING → READY → RUNNING → WAITING_FOR_APPROVAL → BLOCKED → SUCCEEDED / FAILED / CANCELLED` with valid transitions.
- Worker registry with metadata (ID, role, tools, status, health).
- Parallel task dispatch with concurrency limits, resource locking, dependency tracking, and unproductive-loop detection.
- Duplicate-dispatch prevention against retries or repeated UI requests.
- Run state persistence (`inspect`/`resume`).

| Capability | Existing Reuse | Files to Create/Modify | Dependencies | Security Implications | Tests | Acceptance Criteria |
|---|---|---|---|---|---|---|
| Worker registry + metadata | `engines/worker.py` (single engine worker), `agents/base_agent.py` | `core/worker_registry.py` (`Worker` metadata + status + health) | No new dependencies | Workers do not automatically inherit all tools | Registration, capability reporting, health check tests | Each worker reports only its authorized capabilities and tools |
| Task states and transitions | `core/run_control.py` (simple run states) | `core/task_lifecycle.py` (task state machine + run ID) | No new dependencies | Prevent duplicate dispatch of the same task | State tests; invalid transitions rejected | Every task state is defined and queryable via API |
| Task coordinator | `orchestrator/router.py` (lightweight) | `core/coordinator.py` (dispatches tasks to workers) | `asyncio`, existing `RunController` | Concurrency caps, timeouts | Dispatch, parallelism, cancellation, duplicate-dispatch tests | Independent tasks run in parallel; cancellation halts work |
| Run state persistence | In-memory only today | `core/run_persistence.py` (optional JSON/SQLite) | No new dependencies | No secrets in persistent store | Save/restore state tests | Interrupted runs can be inspected or resumed |

### Phase D — Shared Blackboard + Evidence + Event Log

**Objectives:**
- Persist `SharedEvidenceGraph` (currently in-memory only) — reuse existing DB if present, otherwise minimal storage.
- Entities: `Run`, `Worker`, `Task`, `Evidence`, `Hypothesis`, `DeadEnd`, `ToolExecution`, `Event` (per spec).
- Event bus with persistent history, per-run events, replay, reconnection, and bounded retention.
- No silent overwriting of another worker's evidence. Immutable event history.
- No raw credentials on the blackboard.

| Capability | Existing Reuse | Files to Create/Modify | Dependencies | Security Implications | Tests | Acceptance Criteria |
|---|---|---|---|---|---|---|
| Evidence persistence | `core/shared_evidence.py` (in-memory) | `core/evidence_store.py` (persistent storage wrapper) | SQLite or existing file store | No raw secrets | Add/read evidence, provenance, credibility tests | Evidence preserves provenance, credibility, and run link |
| Persistent event bus | Simple `BaseAgent.emit()` | `core/event_bus.py` (ordered per-run persistent events) | `asyncio` | Sanitize events before publishing | Ordering, replay, retention limit tests | Per-run events are ordered and accessible via API |
| Dead-end / Hypothesis tracking | Absent | `core/evidence_store.py` (`Hypothesis`/`DeadEnd` entities) | No new dependencies | Never claim confirmation without evidence | Evidence-to-hypothesis linking, dead-end logging tests | Hypotheses require supporting evidence |

### Phase E — Safe Tool Adapters (CLI / MCP / Coding Agents) ✅ Complete (This Session)
- `core/mcp_config.py` — MCP server config schema (Pydantic: `server_id`, transport, command, auth, per-tool permissions).
- `core/mcp_client.py` — Real MCP client (stdio via `asyncio` subprocess, JSON-RPC 2.0, `initialize`, `tools/list`, `tools/call`, cancellation, bounded reconnect retry, audit log) + `MCPClientManager` for multi-server namespaces.
- `core/coding_agent_adapter.py` — Abstract `CodingAgentAdapter` + `CLICodingAgentAdapter` (Codex/Claude/OpenCode via argv only, authorized workspace, diff review before apply, cancellation, timeout) + `CodingAgentRegistry` with capability matrix.
- `core/tool_registry.py` — `MCPTool` wrapper + `register_mcp_tools()` bridging MCP tools into the composite registry.
- `config/mcp.example.json` — Example config (no secrets).
- `docs/mcp-setup.md`, `docs/coding-agent-setup.md` — Setup and security documentation.
- `tests/test_mcp_client.py` (11), `tests/test_coding_agent_adapter.py` (19) — all passing.

### Phase G — Sandbox + Network Scope Enforcement ✅ Complete (Previous Session)
- `core/sandbox.py` (`LocalSandbox` + documented `DockerSandbox`).
- `core/scope_enforcer.py` (`ScopeEnforcer`: blocks metadata/loopback/RFC1918, validates redirects, rate limits, audit log).
- Wired `CliTool.execute` to `LocalSandbox` + `CliTool.authorize` to `ScopeEnforcer`.

### Phase H — API / Frontend + Monitoring ✅ Partial (Previous Session)
- `core/global_state.py`, `ui/web/runs_api.py`, `/api/runs/{id}/events\|evidence\|findings`.

**Objectives:**
- Safe CLI adapter: argument arrays, executable path validation, rejection of unexpected names, timeout, output truncation, JSON output parser, no shell strings.
- Official MCP client using a supported SDK: multi-server, tool discovery, authorized invocation, cancellation, disconnect detection, bounded reconnect, separate namespaces.
- Coding agent adapters (Codex/Claude Code/Cursor/OpenCode): common interface, binary existence check, auth, authorized working directory, timeout, bounded output, cancellation, capability matrix.
- Diff review before high-impact edits. No file access outside the authorized workspace.

| Capability | Existing Reuse | Files to Create/Modify | Dependencies | Security Implications | Tests | Acceptance Criteria |
|---|---|---|---|---|---|---|
| Safe CLI adapter | `agents/nmap_agent.py` etc. (individual tools) | `core/cli_adapter.py` (safe execution, executable allowlist) | No new dependencies | No shell strings, allowlist, path validation | Argv array, disallowed name rejection, timeout tests | Every CLI command executes as an argv array, never a shell string |
| MCP client | `core/mcp_server.py` (server only) | `core/mcp_client.py` (official client, discovery, invocation) | Supported MCP SDK | Authorization independent of server claims; server cannot modify policy | Discovery, call, server error, reconnect tests | MCP servers are discovered and called through the unified interface |
| Coding agent adapter | `engines/drivers/` (claude/codex/opencode) | `core/coding_agent_adapter.py` (common interface + diff review) | Installed binaries for review | Authorized workspace only; no secrets/SSH access | Tool check and accurate capability reporting tests | Each agent reports only its actual capabilities |

### Phase F — Burp Integration + Editors

**Objectives:**
- Burp adapter built on a real documented interface for the target edition (not GUI scraping by default).
- Operations: `health_check`, `retrieve_authorized_http_history`, `retrieve_request`/`response`, `submit analysis job`, `import`/`export findings`.
- Redact cookies / `Authorization` headers / tokens before sending to models. Record provenance for every finding. Degrade gracefully if Burp is unavailable.
- Optional editor adapters only where the editor API supports the required operations.

| Capability | Existing Reuse | Files to Create/Modify | Dependencies | Security Implications | Tests | Acceptance Criteria |
|---|---|---|---|---|---|---|
| Burp adapter | `agents/burp_agent/` + `validate_burp_*.py` | `core/burp_adapter.py` + config + secret-free setup docs | Real Burp interface | Sanitize sensitive data; never claim confirmation without evidence | Adapter tests (unit mocks; isolated env for integration) | Implemented Burp features use an actually documented interface |
| Editor adapters | Absent | `core/editor_adapter.py` (optional) | Supported editor API | Never claim GUI control for plain CLI commands | Capability reporting tests | Features are optional and clearly documented |

### Phase G — Sandbox + Scope Enforcement + Human Approvals + Secret Redaction

**Objectives:**
- Run untrusted code and offensive tools inside a dedicated container or VM.
- Restricted working directory, process timeouts, resource limits, network policy, read-only mounts, restricted env vars, non-root execution where possible, artifact limits, temp cleanup, process-tree termination, audit log.
- Authoritative scope policy: hostnames, IP addresses/ranges, ports, protocols, exclusions, time windows, rate limits. Re-validate on redirects. Block local metadata services, loopback, and private networks unless explicitly authorized.
- Human approvals for high-risk actions (Approve/Reject/Pause/Resume/Cancel), bound to the specific action, its parameters, and policy context. No agent self-approval for high-risk actions.
- Redact secrets across logs, prompts, blackboard, events, and error reports. Sanitize HTTP headers and cookies.

| Capability | Existing Reuse | Files to Create/Modify | Dependencies | Security Implications | Tests | Acceptance Criteria |
|---|---|---|---|---|---|---|
| Sandbox | `docker/worker*.Dockerfile` exists | `core/sandbox.py` (container/isolation runner) | Docker if available | Never expose full host to untrusted workers | Isolation and resource limit tests | Worker executes inside a verifiably constrained container |
| Network scope enforcement | `core/scope_guard.py` (partial) | `core/scope_enforcer.py` (runtime check, redirects) | No new dependencies | Deny out-of-scope; no DNS/redirect bypass | Scope, out-of-scope denial, redirect tests | Every network operation is scope-checked at runtime |
| Human approvals | `run_control.py` pause/resume/stop exists | `core/approvals.py` (action-bound approval request) | No new dependencies | No self-approval; timeout never turns denied into allowed | Approve/reject/timeout tests | High-risk operations wait for approval |
| Secret redaction | `credential_env` via env (not argv) | `core/secret_redactor.py` (log/event/error sanitization) | No new dependencies | Zero secrets in any output | Header/cookie/token sanitization tests | No secret appears in any log, event, or evidence |

### Phase H — API / Frontend + Monitoring + Documentation

**Objectives:**
- Run endpoints: `POST /runs`, `GET /runs`, `GET /runs/{id}`, `POST pause/resume/cancel`, `GET /events`, `GET /evidence`, `GET /findings`.
- Authentication, authorization, input validation, rate limits, structured errors, pagination, event streaming, cancellation semantics.
- No unauthenticated admin UI. No binding to public interfaces without protection.
- Configuration views for providers, workers, tools, MCP servers, Burp, sandbox, scope, and policy. Honest status display (`configured` / `connected` / `disconnected` / `unsupported` / `awaiting credentials`).

| Capability | Existing Reuse | Files to Create/Modify | Dependencies | Security Implications | Tests | Acceptance Criteria |
|---|---|---|---|---|---|---|
| Run endpoints | `/api/runs/*` exists in `control_api.py` | `ui/web/runs_api.py` (expansion), events | FastAPI | Auth/authz on every endpoint | API, pagination, cancellation tests | Every endpoint enforces access control |
| Event streaming | Absent | `core/event_bus.py` → WebSocket in `app.py` | `asyncio` | Sanitize before broadcast | Streaming and reconnect tests | Frontend receives live run events |
| Configuration views | Existing tabs in `index.html` | `ui/web/templates/` (expansion) | No new dependencies | Honest status; never report healthy just because config keys exist | UI tests (where applicable) | Every integration shows real status |
| Documentation | Absent | `docs/architecture.md`, `docs/agent-runtime.md`, etc. | No new dependencies | No secrets in docs | Manual review | Documentation matches implementation |

### Phase I — Full Test Suite + Security Review + Final Report

| Item | Criterion |
|---|---|
| All existing tests pass | Zero regressions in 1709+ tests |
| New tests for every feature | Coverage for registry, authorization, states, events, redaction |
| External integration tests marked as environment blockers | Never claim external tests passed using mocks alone |
| Security review of sensitive code | Authorization, scope, secrets, sandbox |
| Final report | Distinguishing implemented / tested / partial / blocked |

---

## Proposed Added Dependencies (Only If Required for Live Execution)

| Package | Purpose | Phase |
|---|---|---|
| `pydantic` (if not present) | Tool schema definitions | B |
| `mcp` (official SDK) | MCP client | E |
| `httpx` | HTTP clients for Burp/MCP | E/F |
| `docker` (Python SDK, optional) | Sandbox container control | G |

No security tool is installed automatically; all CLI integrations are optional and configured by the operator.

---

## Definition of Done for This Project

1. Application starts without errors.
2. Existing functionality continues to work (no regressions).
3. New architecture is integrated into the live application (not a separate app).
4. Workers can be registered and assigned tasks.
5. Coordinator tracks task and worker states.
6. Tool calls are validated and authorized before execution.
7. CLI execution uses argument arrays.
8. MCP servers can be configured and discovered over the supported protocol.
9. Burp adapter uses real documented capabilities for its implemented features.
10. Coding agent integrations report their capabilities accurately.
11. Evidence is stored with provenance.
12. False positives and unconfirmed hypotheses are represented accurately.
13. Long-running tasks can be monitored and cancelled.
14. High-risk actions enforce approval requirements.
15. Scope enforcement applies to network operations.
16. Secrets are never exposed in logs or evidence.
17. Automated tests pass (aside from clearly documented environmental blockers).
18. Documentation matches actual implementation.
19. No critical integration is represented by a placeholder while described as complete.
20. Final report distinguishes implemented / tested / partial / blocked.

---

## Completed Implementation (Updated — Actual Status as of Current Session)

### Phase A — Audit and Baseline ✅ Complete
- `docs/architecture-audit.md` — Full audit of existing architecture and gaps.
- `docs/implementation-plan.md` — This plan.
- Baseline: 1709 collected tests (1701 passing, 7 pre-existing failures in `*_pilot.py` unrelated to this work, 1 skipped).

### Phase B — Shared Interfaces + Configuration + Tool Registry + Authorization ✅ Complete
- `core/agent_provider.py` — Unified `AgentProvider` interface (`capabilities` / `health_check` / `execute` / `stream` / `cancel`) + `StubProvider` + provider registry. No secrets in errors.
- `core/tool_registry.py` — Composite tool registry (`ToolDefinition`, `Tool`, `CliTool`, `ToolRegistry`) enforcing the sequence: schema validation → worker authorization → scope → risk policy → human approval → argv execution → output limit → audit → secret redaction.
- `tests/test_agent_provider.py` (10), `tests/test_tool_registry.py` (18) — all passing.

### Phase C — Task Coordinator + Worker Registry + Lifecycle + Cancellation ✅ Complete
- `core/planner/interface.py` — `Planner`/`DefaultPlanner` interface added to the existing `core/planner` package (no collision with `StateSpacePlanner`).
- `core/task_lifecycle.py` — Task state machine (`PENDING→READY→RUNNING→WAITING_FOR_APPROVAL→BLOCKED→SUCCEEDED/FAILED/CANCELLED`) with valid transitions and duplicate-dispatch prevention.
- `core/worker_registry.py` — Worker registry with metadata, task assignment/completion, health checks, and available workers per role.
- `core/coordinator.py` — Task coordinator: `submit_run`, planner, worker assignment, concurrent execution with semaphore, resource locks via `SharedEvidenceGraph`, bounded retries, human approval, cancellation, persistent per-run event log, final summary.
- `tests/test_coordinator_phase_c.py` (14) — all passing.

### Phase D — Persistent Shared Blackboard + Event Log ✅ Complete
- `core/evidence_store.py` — Thread-safe persistent evidence store (JSONL in `data/evidence_store/`) with `Evidence`/`Hypothesis`/`DeadEnd`/`ToolExecution`/`Event`/`Run` entities, secret redaction, content hash (tamper detection), append-only (latest record wins), and `get_events` for history replay.
- `engines/worker.py` — `EngineWorker` now persists every run result to both `SharedEvidenceGraph` **and** `EvidenceStore` (optional/additive; does not break runs when omitted).
- `tests/test_evidence_store.py` (12) — all passing.

### Summary of New Tests (Current)
| Suite | Tests | Status |
|---|---|---|
| agent_provider | 10 | ✅ |
| tool_registry | 18 | ✅ |
| coordinator_phase_c | 14 | ✅ |
| evidence_store | 12 | ✅ |
| engines_cli_workers (incl. evidence wiring) | 24 | ✅ |
| flags_pipeline | 18 | ✅ |
| run_control_and_budget | 17 | ✅ |
| ctf_platforms | 14 | ✅ |
| ctf_flag_bridge | 10 | ✅ |
| extensions_system | 22 | ✅ |
| shared_evidence_graph | 18 | ✅ |
| new_api_smoke | 6 | ✅ |
| runs_api | 2 | ✅ |
| sandbox | 6 | ✅ |
| scope_enforcer | 11 | ✅ |
| mcp_client | 11 | ✅ |
| coding_agent_adapter | 19 | ✅ |
| burp_adapter | 16 | ✅ |
| action_evaluator_and_policy (pre-existing) | 4 | ✅ |
| **Total** | **252** | ✅ **All passing** |

### Phase F — Burp Integration ✅ Complete (This Session)
- `core/burp_adapter.py` — Stable Burp adapter with 9 documented operations (`health_check`, `get_available_capabilities`, `retrieve_authorized_http_history`, `retrieve_request`, `retrieve_response`, `submit_supported_analysis_job`, `retrieve_analysis_results`, `import_supported_findings`, `export_supported_findings`).
- Layered over existing infrastructure (`core/burp_gateway/`): local gateway, traffic store, finding exporter (`BurpIssueExporter`), provenance engine.
- Explicitly documented: Burp exposes no public official REST API; integration works via a Burp extension (BApp) forwarding traffic to the local gateway.
- Security controls: redacts cookies/`Authorization`/tokens, records provenance per finding, never claims confirmation without a real tool, degrades gracefully when Burp is unavailable.
- `config/burp.example.json` — Example config (no secrets).
- `docs/burp-setup.md` — Setup and security guide.
- `tests/test_burp_adapter.py` (16) — all passing (mocked, no external systems).

### Phase G — Sandbox + Network Scope Enforcement ✅ Complete (Previous Session)
- `core/sandbox.py` — Abstract `Sandbox` + `LocalSandbox` (local execution via `create_subprocess_exec` with no shell string, restricted `cwd`, restricted `env`, timeout with process termination, output cap) + documented `DockerSandbox` for Kali/server execution.
- `core/scope_enforcer.py` — `ScopeEnforcer` wrapping existing `core/scope_guard.py`: blocks metadata services (`169.254.169.254`, `metadata.google.internal`), blocks loopback/RFC1918 unless authorized, validates redirects against scope, enforces per-target rate limits, and logs every scope decision.
- `core/tool_registry.py` — `CliTool` now executes via `LocalSandbox.run` instead of direct `create_subprocess_exec`; `CliTool.authorize` invokes `ScopeEnforcer.enforce_target` when available.
- `tests/test_sandbox.py` (6), `tests/test_scope_enforcer.py` (11) — all passing.

### Phase H — API / Frontend + Monitoring ✅ Partial (Completed in Previous Session)
- `core/global_state.py` — Shared singletons `GLOBAL_COORDINATOR` and `GLOBAL_EVIDENCE_STORE` (mirroring `GLOBAL_RUN_CONTROLLER`).
- `ui/web/runs_api.py` — Endpoints:
  - `GET /api/runs/{run_id}/events` — Event history for a run.
  - `GET /api/runs/{run_id}/evidence` — Evidence linked to a run.
  - `GET /api/runs/{run_id}/findings` — Confirmed findings (`proof`/`anomaly`/`contradicted`).
- Mounted `runs_api_router` in `ui/web/app.py` (after control/budget).
- `tests/test_runs_api.py` (2) — passing.
- Remaining in Phase H: frontend display views + detailed documentation.

### Phase I — Full Test Suite + Security Review + Final Report ✅ In Progress
- 206 new tests all passing (incl. `sandbox` + `scope_enforcer`).
- 7 pre-existing failures in `*_pilot.py` documented and unrelated to this work.
