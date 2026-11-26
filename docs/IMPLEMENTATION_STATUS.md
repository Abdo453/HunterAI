# HunterAI — Implementation Status Tracker
# حالة التنفيذ الموحد لمنصة HunterAI

> **Branch:** `feat/platform-unification`
> **Completed Gates:** `phase/0-green` through `phase/7-green` (Phase 8 release hardening in progress)
> **Scope Note:** This tracker reflects verified repository structure and git milestones. Test pass counts are intentionally not hard-coded here; run the verification commands in Section 4 to obtain live counts for the current checkout.

---

## 1. Platform Unification Milestone Tags

| Milestone | Git Tag | Commit | Summary |
| :--- | :--- | :--- | :--- |
| Pre-Unification Baseline | `baseline/pre-unification` | `d5dd2bb6` | Safety baseline prior to Phase 0 external reference isolation |
| Phase 0 — Isolation & Provenance | `phase/0-green` | `bbd3f723` | Pinned read-only `external/` checkouts, `.gitignore`/`.dockerignore`/`pyproject.toml` boundaries, `NOTICE`, AGPL-3.0 ban |
| Phase 1 — Service Security Hardening | `phase/1-green` | `76f8b9f5` | Django local bearer auth, PBKDF2-SHA512 KDF, `sgn` revocation, `userTier`/`tokenTier`, CSRF/Origin/WS/CSP, editor sandbox, subprocess allowlist, approval digest, Burp/Go/MCP hardening |
| Phase 2 — Canonical Runtime | `phase/2-green` | `59fd1bf4` | `RuntimeOrchestrator`, 7-state run lifecycle, checkpointing, idempotency, crash recovery, API/Go parity |
| Phase 3 — 7-State Evidence Court | `phase/3-green` | `c017b8e3` | Authoritative 7-state `CourtVerdict`, typed `ProofContract`, PoE truthfulness invariants |
| Phase 4 — Skills, Tools & Sandbox | `phase/4-green` | `0fced3af` | `config/tools.catalog.yaml` (68 tools), hardened `DockerSandbox`, `skills/registry.json` (`hunterai-redteam`), dual-channel `core/prompts/`, 8 Apache-2.0 PentesterFlow corpora |
| Phase 5 & 6 — Sensors, Vuln Intel & AI Infra | `phase/5-6-green` | `79ce0ccf` | Sensory Triad seam fixes, `core/vuln_intel/` API wiring, `LLMRouter`, `core/context/` AST compaction, `GPUScheduler`, fail-closed `core/security_mode.py` |
| Phase 7 — Unified Frontend UI | `phase/7-green` | `0111cdd2` | Next.js Obsidian Sentinel dashboard (`frontend/app/`), live Copilot UI, WCAG contrast & Arabic RTL hardening |
| Phase 8 — Release Hardening | *(in progress)* | `feat/platform-unification` | Hardened Docker/Compose (`:8088` WAF lab), full multi-stack CI matrix, E2E/VRAM alignment, zero-caller dead-code retirement, documentation reconciliation |

---

## 2. Active Subsystem Inventory (Source-Verified)

| Domain | Status | Canonical Modules | Notes |
| :--- | :---: | :--- | :--- |
| **Control Plane (Django ASGI `:8000`)** | ✅ Active | `hunter_backend/{asgi,auth,middleware,runtime,settings,urls,websocket}.py`, `hunter_backend/apps/*` | ~252 HTTP routes + authenticated WS/SSE streams; canonical API control plane |
| **Go ARTEX-Pro Engine (`127.0.0.1:7071`)** | ✅ Active | `backend/cmd/server/`, `backend/internal/{api,agent,arsenal,database}/` | Constant-time bearer auth, strict CORS allowlist, private/metadata SSRF block, PostgreSQL persistence |
| **Obsidian Sentinel Frontend (`:3000`)** | ✅ Active | `frontend/app/{page,operations,surface,intercept,findings,arsenal,studio,system}` | Next.js App Router, Copilot SSE streaming, WCAG & RTL support |
| **Canonical Runtime Orchestrator** | ✅ Active | `core/runtime/{orchestrator,state_machine,event_bus,agent_manager}.py` | Single dispatcher with `Flow -> Task -> Subtask` checkpoints and `recover_run()` |
| **7-State Evidence Court & PoE** | ✅ Active | `core/evidence_court.py`, `core/poe_engine.py`, `core/court/evidence_court_v2.py` | Canonical states: `UNVERIFIED`, `CANDIDATE`, `CONFIRMED`, `REJECTED`, `INCONCLUSIVE`, `UNAVAILABLE`, `ERROR` |
| **Sensory Triad** | ✅ Active | `core/sensors/sensory_triad.py`, `core/browser/`, `core/burp_gateway/`, `core/code_intel/` | Browser Playwright sensor, Burp Gateway (`127.0.0.1:8085`), JS/AST code intelligence |
| **Vulnerability Intelligence** | ✅ Active | `core/vuln_intel/{models,db,sync,coverage,cvss,php,triage,tool_selection,cli}.py`, `sources/{nvd,osv}.py` | Wired into `/api/vuln-intel/{search,coverage,triage,sync}` |
| **Tool Catalog & Sandbox** | ✅ Active | `config/tools.catalog.yaml`, `core/tool_registry.py`, `core/sandbox.py`, `scripts/sync_tool_manifests.py` | 68 tools / 13 tiers / 2 MCP entries; `DockerSandbox` drops all caps (`CapDrop: ALL`) |
| **Skills, Prompts & Wordlists** | ✅ Active | `skills/registry.json`, `skills/hunterai-redteam/`, `core/prompts/`, `wordlists/pentesterflow/` | 1 canonical skill mirrored to `.opencode/skills/` and `.agents/skills/`; 8 Apache-2.0 corpora |
| **LLM Router, Context & VRAM** | ✅ Active | `core/llm_router.py`, `core/context/`, `core/llm/gpu_scheduler.py` | Policy routing (`cloud_first`/`local_first`/`local_only`/`cloud_only`), AST compaction, priority GPU lock |
| **Fail-Closed Security & Red-Team Policy** | ✅ Active | `core/security_mode.py`, `core/policy/red_team.py`, `core/network_scope_guard.py`, `core/scope_guard.py` | Defaults `unrestricted_mode()=False`, `web_governance_enforced()=True`; HMAC-signed grants |
| **Safe Read-Only Detectors** | ✅ Active | `core/detectors/` | SQLi, XSS, IDOR, SSRF (loopback canary), open-redirect + `EvidenceChain` + `LabValidationGate` |
| **Blue-Team Detection Pack** | ✅ Isolated | `detections/{sigma,suricata,attack,indicators,triage,tests}/` | Static defensive detection library; isolated from offensive runtime execution |
| **Upstream Reference Isolation** | ✅ Enforced | `external/` (gitignored), `NOTICE`, `THIRD_PARTY_LICENSES/`, `tests/test_external_isolation.py` | `github.com/vxcontrol/cloud` (AGPL-3.0) banned across repository |

---

## 3. Phase 8 Dead-Code Audit Record

Static caller analysis across tracked repository files (excluding `external/` and `.git/`) verified which legacy candidates could be safely removed without breaking runtime, CLI, script, or test callers:

| Candidate | Decision | Evidence |
| :--- | :--- | :--- |
| `claude-red/` | **Deleted** | Orphaned gitlink (`160000`, no `.gitmodules`, empty working dir); 0 references repo-wide |
| `core/orchestrator.py` | **Deleted** | Superseded v2.0 orchestrator (`AnalystAgent`, `ValidationAgent`); 0 runtime, CLI, script, or test callers (only historical audit mentions) |
| `plugins/sample_exporter/` | **Deleted** | Sample plugin (`manifest.json`, `plugin.py`); 0 external references (`PluginLoader.discover_and_load_all()` handles empty `plugins/` cleanly) |
| `rules/*.md` | **Deleted** | `rules/{README,hunting,reporting}.md`; 0 references repo-wide (canonical guidance consolidated in `skills/hunterai-redteam/` and `AGENTS.md`) |
| `core/pipeline_runner.py` | **Retained** | Active test caller: `tests/test_platform_unified.py:210,265,466,542` |
| `core/smart_orchestrator.py` | **Retained** | Active test callers: `tests/test_ai_model_connectivity.py:9,104`, `tests/test_auto_route_streaming.py:62,87,102`, `tests/test_llm_streaming.py:206` |
| `agents/autonomous_mission_agent.py` | **Retained** | Active test callers: `tests/test_agent_improvements.py:19-23`, `tests/test_cognitive_architecture.py:19`, `tests/test_mission_framework.py:14` |
| `core/pipeline/authorized_bugbounty_pipeline.py` | **Retained** | Active test caller: `tests/test_authorized_bugbounty_pipeline.py:11-16` |

---

## 4. Verification Commands

Execute these commands to verify the current working tree across all three stacks:

```bash
# 1. Isolation, security, and Phase 2-6 contract suites
python -m pytest tests/test_external_isolation.py tests/security/ tests/test_canonical_runtime_contracts.py tests/test_evidence_court_truthfulness.py tests/test_registry_parity.py tests/test_cross_platform_sandbox.py tests/test_prompt_templates.py tests/test_sensory_triad_and_vuln_intel.py tests/test_llm_context_vram.py -q

# 2. Hermetic Python suite + full-platform E2E
python -m pytest tests/ -q -m "not slow" --ignore=tests/integration
python -m pytest tests/integration/test_full_platform_e2e.py -q

# 3. Registry, manifest, readiness, arena, and certification gates
python tools/install_opencode_skills.py --check
python scripts/sync_tool_manifests.py --check
python run_causal_validation_arena.py
python -m core.readiness --timeout 5
python certify.py

# 4. Go ARTEX-Pro backend
cd backend && go test -race ./...

# 5. Next.js Obsidian Sentinel frontend
cd frontend && npm run lint && npx tsc --noEmit --incremental false && npm run build && npm run verify:ui
```
