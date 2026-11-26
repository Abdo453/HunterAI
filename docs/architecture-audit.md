# Architecture & Gap Analysis

**Repository:** `E:\Agant\PentestAI-Unified` (HunterAI / PentestAI-Unified)
**Language / Framework:** Python 3.11 + FastAPI (web UI on port 7070), entry point `main.py`
**Package Manager:** `requirements.txt` + `pyproject.toml` (`hunterai` package)
**License:** MIT (new code written from scratch — not copied from Muteki AGPL-3.0)
**Tests before this session:** 1709 collected
**Tests after this session:** 133 new subsystem tests + baseline project state

---

## 1. Core Entry Points

| File | Role |
|---|---|
| `main.py` | Main entry point launching the FastAPI application |
| `ai_agent_v2_enhanced.py` | Enhanced agent (v2) |
| `bugbounty_agent.py` | Standalone Bug Bounty agent |
| `run_unified_live_session.py` | Unified live session runner |
| `validate_burp_*.py` | Burp integration validation scripts |
| `cli/` | Command-line interface |
| `ui/web/app.py` | Main FastAPI application with mounted routers |

## 2. Existing Orchestrator / Multi-Agent Layers

| Layer | File | Summary |
|---|---|---|
| Lightweight orchestrator | `orchestrator/router.py`, `task_classifier.py`, `resource_manager.py` | Task classification and routing |
| Autonomous brain orchestrator | `hunter_ai/brain/orchestrator_workers.py` | Worker coordination in brain layer |
| Cognitive council | `hunter_ai/brain/cognitive_council.py` | Multi-model decision coordination |
| Model router | `core/llm_router.py` | Routes LLM calls across providers |
| Tool manager | `tools/tool_manager.py` (used by `agents/base_agent.py`) | Manages agent tools |
| Base agent | `agents/base_agent.py` | `BaseAgent` with `AgentTask` / `AgentResult` and event `emit()` |
| Security agents | `agents/nmap_agent.py`, `ffuf_agent.py`, `nuclei_agent.py`, `semgrep_agent.py`, `burp_agent.py`, `katana_agent.py`, `httpx_agent.py`, etc. | Tool-specific security agents |

## 3. Newly Added Subsystems (Additive — All Tests Passing)

| Subsystem | Package | Capabilities |
|---|---|---|
| CLI engine agents | `engines/` | Drivers for Claude Code / Codex / OpenCode with `secure_prompt_transport` (secrets via env, not argv) |
| CTF flag pipeline | `flags/` | Candidate extraction, deduplication, ranking, false-positive filtering, multi-flag progress |
| CTF platforms | `ctf/` | CTFd / rCTF / GZCTF clients + `SubmitThrottler` (ban protection) |
| CTF ↔ FlagService bridge | `ctf/bridge.py` | Automated candidate submission with cooldown and early stop |
| Run control | `core/run_control.py` | `RunController` with pause/resume/stop + cooperative checkpoints (`checkpoint()`) |
| Cost & budget | `core/cost_budget.py` | `CostController` with circuit breaker + `is_over_budget()` |
| Shared evidence graph | `core/shared_evidence.py` | Thread-safe Facts / Intents / Locks / InsightBus |
| Extension system | `extensions_ext/` | Fail-closed manifest, trust levels, per-call authorized `HostAPI` |
| Engines web API | `ui/web/engines_api.py` + tab in `index.html` | GET/POST `/api/engines/*` |
| Control web API | `ui/web/control_api.py` | `/api/runs/*`, `/api/budget` |
| Docker images | `Dockerfile`, `docker/worker.Dockerfile`, `docker/worker-kali.Dockerfile` | Web + lightweight worker + full Kali worker |
| Python package | `pyproject.toml` | `hunter` / `hunterai` entry points |

## 4. Gaps Against "MASTER IMPLEMENTATION SPECIFICATION"

| Required Capability | Status | File / Note |
|---|---|---|
| Unified agent API (`AgentProvider`) | ✅ Partial | `engines/base.py` `EngineDriver` covers CLI agents only, not all LLM providers |
| LLM providers with tool-calling / streaming / cost | ✅ Partial | `core/llm_router.py` exists; no unified `AgentProvider` interface with `health_check` / `cancel` |
| Task coordinator/orchestrator with task states (`PENDING`..`CANCELLED`) | ❌ Missing | `RunController` manages asyncio runs only, not multi-worker task lifecycles |
| Task registry with dependencies and task relationships | ❌ Missing | |
| Resource locking to prevent worker conflicts | ✅ Partial | `SharedEvidenceGraph.acquire_lock()` is in-memory only |
| Unified Tool Registry with schema + permissions + risk level | ❌ Missing | `agents/` uses existing `ToolManager`, which does not match the spec `Tool` interface |
| CLI execution via argument arrays (no shell strings) | ⚠️ Partial | `engines/runner.py` uses subprocess safely, but lacks a general tool registry with allowlist |
| Official MCP client integration | ❌ Missing | `core/mcp_server.py` is a server, not an MCP client |
| Real Burp Suite integration | ⚠️ Partial | `agents/burp_agent/` + `validate_burp_*.py` exist — needs audit to verify real API vs GUI scraping |
| Coding agent integration (Codex/Claude Code/Cursor/OpenCode) | ✅ Partial | `engines/drivers/` covers claude/codex/opencode as CLI workers only |
| Shared evidence blackboard with provenance and confidence | ✅ Present | `core/shared_evidence.py` (in-memory only, not persisted) |
| Validation / false-positive control | ✅ Partial | `flags/` covers CTF flags only, not general security findings |
| Event bus with persistent history and replay | ❌ Missing | `BaseAgent.emit()` is basic, not a persistent event bus |
| Human-in-the-loop control (approve/reject/pause/resume) for high-risk ops | ⚠️ Partial | pause/resume/stop exist in `run_control`; no approval workflow for high-risk operations |
| Scope enforcement on network operations | ⚠️ Partial | `core/scope_guard.py` (used by `engines_api.py`) — needs verification of full network coverage |
| Secret management without log leakage | ⚠️ Partial | `credential_env` passed via env instead of argv — needs logging audit |
| Frontend run / stop / events UI | ✅ Partial | `/api/runs/*` exists; no dedicated run control screen beyond existing web UI tabs |
| Integration tests for external systems (MCP / Burp / live network) | ❌ Missing | Mock tests only |

## 5. Execution Summary

The system is currently **stable with all tests passing** (133 new subsystem tests). The additions cover a substantial portion of the specification safely (additive changes, removing no existing functionality).

Critical remaining gaps (ordered by specification Phases B → I):
1. **Phase B:** Unified LLM provider interface + composite tool registry + permission policy.
2. **Phase C:** Task coordinator with lifecycle states + worker assignment + cancellation.
3. **Phase D:** Blackboard persistence (currently in-memory only) + persistent event log.
4. **Phase E/F:** Native MCP client + Burp adapter + coding agent adapters with diff review.
5. **Phase G:** Sandboxing + network scope enforcement + human approvals + secret redaction.
6. **Phase H:** Run control web UI + documentation.
7. **Phase I:** Full test suite + security review + final report.

## 6. Acceptance Criteria (Interim Until Phase B–I Completion)

1. Application starts cleanly (`main.py` / `app.py` import without errors).
2. All existing tests pass with zero regressions.
3. Workers register and receive assigned tasks through the new interface.
4. Tool invocations are validated and authorized before execution.
5. CLI execution uses argument arrays.
6. Long-running sessions can be stopped and monitored via `/api/runs/*`.
7. Secrets never appear in logs or evidence artifacts.
8. Documentation matches the actual implementation.
