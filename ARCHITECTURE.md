# HunterAI — Unified Platform Architecture

HunterAI is a multi-stack autonomous security testing platform built around deterministic proof verification, fail-closed execution governance, and strict isolation between untrusted external data, offensive tool adapters, and blue-team detection assets.

---

## 1. Service & Process Topology

```text
                    +-------------------------------------+
                    |  Next.js Obsidian Sentinel UI       |
                    |  frontend/  (127.0.0.1:3000)        |
                    +------------------+------------------+
                                       | HTTP + SSE + WS (Bearer / CSRF + Origin)
                    +------------------v------------------+
                    |  Django 5.2 + DRF Pure ASGI Plane   |
                    |  hunter_backend/ (127.0.0.1:8000)   |
                    |  ~252 HTTP routes + WS/SSE streams  |
                    +---------+-----------------+---------+
                              |                 |
          +-------------------+                 +--------------------+
          |                                                          |
+---------v-----------------------+             +--------------------v-----------------+
|  Python Core Engine             |             |  Go ARTEX-Pro Concurrency Engine     |
|  core/ + hunter_ai/ + agents/   |             |  backend/ (127.0.0.1:7071)           |
|  - RuntimeOrchestrator          |             |  - /api/v1/{health,stats,scan,...}   |
|  - Sensory Triad + Vuln Intel   |             |  - Constant-time bearer auth         |
|  - ToolRegistry + Sandbox       |             |  - Private/metadata SSRF block       |
|  - LLMRouter + Context + GPU    |             +--------------------+-----------------+
|  - 7-State Evidence Court       |                                  |
+---------+-----------------------+             +--------------------v-----------------+
          |                                     |  PostgreSQL (:5432)                  |
          +----> Burp Gateway (127.0.0.1:8085)  |  Engagements, assets, findings, logs |
          +----> SQLite (PlatformStore, vuln_intel)
          +----> Optional WAF Lab (127.0.0.1:8088, docker-compose.waf-lab.yml)
```

- **Frontend (`frontend/app/`):** Next.js App Router serving `/` (Overview), `/operations`, `/surface`, `/intercept`, `/findings`, `/arsenal`, `/studio`, and `/system`, with live Copilot streaming, WCAG contrast compliance, and Arabic RTL support.
- **Control Plane (`hunter_backend/`):** Single-worker ASGI application (`hunter_backend/asgi.py`) exposing platform orchestration (`/api/platform/*`), Copilot (`/api/copilot/*`), operational runs (`/api/runs/*`), control center & Burp/MCP/sandbox endpoints (`/api/control/*`, `/api/burp/*`, `/api/mcp/*`, `/api/sandbox/*`), vulnerability intelligence (`/api/vuln-intel/*`), and OpenCode/editor APIs (`/api/opencode/*`, `/api/editor/*`).
- **Go ARTEX-Pro (`backend/`):** High-concurrency scanner bound to `127.0.0.1:7071` by default (`ARTEX_BIND_ADDR`), synchronized back into `PlatformStore` via `sync_artex_to_store()`.
- **Burp Gateway (`core/burp_gateway/`):** Local REST bridge on `127.0.0.1:8085` (refuses non-loopback bind unless `HUNTER_BURP_GATEWAY_ALLOW_REMOTE=1`) connecting Burp Suite Proxy/Repeater traffic and the Jython extension (`agents/burp_agent/integrations/burp_extension/`).

---

## 2. Canonical Runtime & Lifecycle Plane (`core/runtime/`)

`core/runtime/orchestrator.py` (`RuntimeOrchestrator`) is the single authoritative dispatcher for managed runs across `live_scanner`, `HunterPipelineOrchestrator`, `OmniHunterEngine`, `VRAMSequentialPipeline`, Go ARTEX-Pro `/api/v1/scan`, and CLI `EngineWorker`.

- **Lifecycle State Machine (`core/runtime/state_machine.py`):** Enforces valid transitions across `QUEUED`, `RUNNING`, `WAITING`, `PAUSED`, `COMPLETED`, `FAILED`, and `CANCELLED` (raising `InvalidStateTransitionError` on illegal jumps).
- **Hierarchical Checkpointing:** Tracks `FlowNode -> TaskNode -> SubtaskNode` progress with atomic JSON persistence (`core/persist/atomic_file.py`), idempotency-key deduplication, bounded cancellation-safe finalization (`run_without_cancel`), and crash recovery (`recover_run()` / `POST /api/platform/runs/<id>/recover`).
- **Event Bus (`core/runtime/event_bus.py`):** `PersistentEventBus` fans out run lifecycle, sensor, approval, and adjudication events to SSE (`/api/platform/stream`) and WebSocket consumers (`hunter_backend/websocket.py`).

---

## 3. Perception Plane: Sensory Triad & Vulnerability Intelligence

### Sensory Triad (`core/sensors/sensory_triad.py`)

1. **Browser Sensor (`core/browser/`):** Persistent Playwright sessions (`session.py`), DOM/auth event routing (`browser_event_bus.py`), application state graph (`state_graph.py`), coverage tracking (`coverage_engine.py`), and information-gain interaction planning (`interaction_planner.py`).
2. **Burp Sensor (`core/burp_gateway/`):** Live HTTP ground truth, Repeater replay, and persistent engagement captures (`capture_store.py`).
3. **Code Intelligence (`core/code_intel/`):** Client-side JavaScript bundle deconstruction, route extraction (`fetch`/`axios`/XHR), and format + Shannon-entropy secret validation.

### Vulnerability Intelligence (`core/vuln_intel/`)

Local SQLite vulnerability store (`db.py`, `models.py`) wired into runtime and control-plane endpoints (`/api/vuln-intel/search`, `/api/vuln-intel/coverage`, `/api/vuln-intel/triage`, `/api/vuln-intel/sync`):

- **Connectors:** NVD 2.0 date-window sync (`sources/nvd.py`, `sync.py`) and OSV/GHSA package query connector (`sources/osv.py`) with CVE alias deduplication and local CVSS v3 scoring (`cvss.py`).
- **Coverage & Triage:** `coverage.py` tracks requested vs observed coverage (`complete=False` unless measured against an explicit denominator); `php.py` classifies PHP runtime/extension/framework/package advisories; `triage.py` evaluates installed package ranges into `CONFIRMED_APPLICABLE`, `LIKELY_APPLICABLE`, `POSSIBLY_APPLICABLE`, `NOT_APPLICABLE`, or `INSUFFICIENT_EVIDENCE`; `tool_selection.py` produces execution plans without running binaries.

---

## 4. AI Routing, Context Compaction & VRAM Governance

### Unified LLM Router (`core/llm_router.py`)

Single routing layer for local Ollama and cloud API providers (`openai`, `anthropic`, `gemini`, `deepseek`, `groq`, `openrouter`) controlled by `HUNTER_LLM_POLICY`:

| Policy | Behavior |
| :--- | :--- |
| `cloud_first` (default) | Prefers configured cloud API keys; falls back to local Ollama |
| `local_first` | Prefers local Ollama; falls back to configured cloud providers |
| `local_only` | Local Ollama only; blocks outbound cloud calls before preference evaluation |
| `cloud_only` | Cloud providers only; skips local Ollama |

### AST Context Compaction & Untrusted Output Framing (`core/context/`)

- **`chain_ast.py` & `token_accountant.py`:** Models conversation chains (`ChainAST`, `Header`, `BodyPair`) and tracks exact byte/token budgets with reserved output room (`MINIMUM_OUTPUT_ROOM`).
- **`compaction.py` & `manager.py`:** Multi-tier compaction (`microcompact_messages`, `compact_chain`, `guard_working_context`, `CompactionCircuitBreaker`, `SessionMemory` pinning) plus HTTP header/body compression and endpoint deduplication.
- **`tool_offload.py`, `truncate.py`, `reconcile.py`:** Offloads oversized tool outputs (`maybe_offload_tool_result`), strips control sequences (`HeadTailBuffer`), reconciles interrupted tool calls (`reconcile_tool_calls`), and wraps untrusted external outputs (`wrap_untrusted_tool_output`) to preserve prompt-injection boundaries.

### Dual-Channel Prompt Templates (`core/prompts/`)

Separates operator-facing UI templates (localized via `{{.Lang}}`) from strict-English technical tool/reasoning templates (forbidden from injecting `{{.Lang}}`), backed by CI template variable validation (`validate_all_templates`) and `ReflectorLoopGuard`.

### GPU / VRAM Scheduler (`core/llm/gpu_scheduler.py`)

Process-wide singleton `get_gpu_scheduler()` serializes local Ollama/LM Studio calls behind an `asyncio.Lock` + priority heap (`PRIORITY_INTERACTIVE = 0`, `PRIORITY_NORMAL = 5`, `PRIORITY_BACKGROUND = 10`) so interactive Copilot requests preempt background scan tasks, with configurable `HUNTER_OLLAMA_KEEP_ALIVE_SEC` and VRAM pressure eviction (default threshold 85%).

---

## 5. Canonical Tool Catalog, Skills & Sandboxing

- **Tool Catalog (`config/tools.catalog.yaml` + `core/tool_registry.py`):** Single source of truth defining 68 security tools across 13 risk/capability tiers (`recon`, `network_scan`, `web_active`, `vuln_scanning`, `exploit_proof`, `tls`, `proxy_orchestration`, `wireless`, `ot_iot`, `credential_review`, `reverse_engineering`, `cloud_posture`, `osint`) plus 2 MCP entries. Derived manifests (`config/tools.json`, `config/tools.yaml`, `tools_mcp.json`) stay synchronized via `python scripts/sync_tool_manifests.py --check`.
- **Execution Sandbox (`core/sandbox.py`):** Shell-free argv invocation with restricted working directory and environment variables. `DockerSandbox` enforces `CapDrop: ["ALL"]` with an explicit capability allowlist (no `SYS_ADMIN`, `SYS_MODULE`, `MKNOD`), `security_opt=["no-new-privileges:true"]`, `pids_limit`, `read_only=True`, image allowlist (`DOCKER_ALLOWED_IMAGES`), and unconditional rejection of `network_mode="host"`, `docker.sock`, or `/` host mounts.
- **Canonical Skill Registry (`skills/registry.json`):** Registers one active project skill, `hunterai-redteam` (`skills/hunterai-redteam/`), mirrored to `.opencode/skills/hunterai-redteam` and `.agents/skills/hunterai-redteam` (`python tools/install_opencode_skills.py --check`). Community packs in `skills_library/` remain inactive intake material.
- **Verified Reference Corpora (`wordlists/pentesterflow/`):** Eight Apache-2.0 wordlists and fingerprint files pinned to `PentesterFlow/agent` commit `0759d87` across `graphql`, `jwt`, `ssti`, `supabase`, and `takeover` (each carrying provenance metadata).

---

## 6. Adversarial Adjudication: 7-State Evidence Court & PoE

`core/evidence_court.py` (`EvidenceCourt`) and `core/poe_engine.py` (`ProofOfExecutionEngine`, `PROOF_CONTRACT_REGISTRY`) prevent any single scanner, agent, or LLM from confirming a vulnerability on heuristics alone.

| Canonical Verdict | Meaning |
| :--- | :--- |
| `UNVERIFIED` | Signal observed or probed without deterministic proof |
| `CANDIDATE` | Reproducible differential signal pending a typed `ProofContract` or causal invariant |
| `CONFIRMED` | Independent deterministic proof satisfied and adjudicated |
| `REJECTED` | Refuted, false positive, disproved, WAF-blocked, duplicate, or out-of-scope (legacy aliases `FALSE_POSITIVE`, `DISPROVED`, `OUT_OF_SCOPE`, `BLOCKED`, `DUPLICATE` map here via `canonical_verdict()`) |
| `INCONCLUSIVE` | Ambiguous or missing verifier result without explicit tool/runtime failure |
| `UNAVAILABLE` | Required verification binary missing, target unreachable, or request timed out |
| `ERROR` | Runtime exception during verifier or proof evaluation |

### Core Epistemic Invariants

1. **No LLM Confirmation Authority:** LLMs generate hypotheses and triage plans; confirmation requires deterministic verifier output matching a `ProofContract` or causal invariant.
2. **Differential Authorization Rule:** An HTTP `200 OK` on an unauthorized request is never confirmed as an auth/IDOR bypass without differential evidence of protected tenant data or unauthorized state change.
3. **Explicit Unknowns:** Absence of findings is never reported as proof of security; unprobed or policy-skipped surfaces remain tracked as coverage gaps.

---

## 7. Fail-Closed Security Boundaries & Isolation

Detailed control-plane controls are documented in [docs/security.md](docs/security.md) and audited in [docs/security_audit.md](docs/security_audit.md). Key architectural invariants:

- **Fail-Closed Mode (`core/security_mode.py`):** `unrestricted_mode()` defaults to `False` (`HUNTER_UNRESTRICTED` opt-in); `web_governance_enforced()` defaults to `True` (`HUNTER_WEB_UNRESTRICTED` opt-in). Neither flag can disable Evidence Court proof requirements, artifact secret scrubbing, cloud metadata/link-local SSRF blocks, dangerous URL scheme blocks, shell metacharacter filtering, or CSRF/Origin enforcement.
- **Signed Authorization Grants (`core/policy/red_team.py`):** `AuthorizationGrant` (HMAC-SHA256) binds scope targets, validity windows, and allowed profiles (`safe`, `standard`, `red_team`) into `ToolRegistry._enforce_policy()`. Hard invariants (persistence/backdoors, C2, lateral movement, destructive writes, evasion, exfiltration, credential dumping) are denied in every profile.
- **Control Plane Hardening (`hunter_backend/`):** CSPRNG bearer auth, PBKDF2-SHA512 domain-separated keys, monotonic session revocation (`sgn`), `userTier` vs `tokenTier` authorization, double-submit CSRF + Origin checks, fail-closed WebSocket Origin/auth, non-code `EDITOR_ALLOWED_ROOTS` (`skills/`, `data/reports/`, `scratch/`), and immutable SHA-256 `proposal_digest` binding on HITL approvals.
- **Upstream Isolation & AGPL-3.0 Ban (`external/`, `NOTICE`):** Upstream references (`external/pentesterflow-agent/` Apache-2.0, `external/pentagi/` MIT) are excluded via `.gitignore`, `.dockerignore`, and `pyproject.toml`. `github.com/vxcontrol/cloud` (AGPL-3.0) is prohibited across all Go and Python source files and enforced by `tests/test_external_isolation.py`.

---

## 8. Isolated Blue-Team Detection Library (`detections/`)

`detections/` ships a standalone defensive artifact pack kept strictly separate from offensive runtime execution:

- **Sigma Rules (`detections/sigma/`):** Five atomic rules and four behavioral correlation rules covering ARTEX-specific telemetry and destructive-command hunting.
- **Suricata Signatures (`detections/suricata/`):** Wire-level User-Agent signatures (`sid 1000001–1000003`).
- **ATT&CK Navigator & Indicators (`detections/attack/`, `detections/indicators/`):** Scored ATT&CK layer, CSV indicators, and import-ready MISP JSON event.
- **Host Triage (`detections/triage/artex_host_triage.py`):** Read-only host inspection script with built-in `--self-test`.
- **Docker Validation Suites (`detections/tests/`):** Reproducible rule validation and drift checks.

---

## 9. Primary CLI Entry Points

| Entry Point | Representative Commands | Purpose |
| :--- | :--- | :--- |
| `pentest.py` | `artex <target>`, `web [target]`, `opencode [target]`, `all <target>`, `recon`, `hunt`, `validate`, `report`, `setup`, `arsenal`, `skills` | Unified stack launcher and bug-bounty CLI workflows |
| `main.py` | `--web`, `--cli`, `--target <url> --mode <recon\|web\|full\|ctf\|hunter\|bugbounty>` | Direct single-target or web-mode entry point |
| `cli/hunter_cli.py` | `scan`, `replay`, `provenance`, `auth-audit`, `identity-matrix`, `sensor-status`, `coverage`, `court-v2`, `constitution`, `external-arena`, `preflight`, `skills` | Cognitive investigation, replay, and audit subcommands |
| `core.readiness` | `python -m core.readiness [--strict] [--timeout N]` | Local environment readiness probe (tools, Ollama, Burp, Playwright, wordlists) |
| `core.detectors.cli` | `demo`, `scan`, `pipeline` | Hermetic read-only detector lab (SQLi, XSS, IDOR, SSRF, open redirect) |
| `core.vuln_intel.cli` | `sync`, `osv-query`, `osv-get`, `coverage`, `search`, `triage`, `select-tools` | Local vulnerability intelligence store & triage CLI |
| `certify.py` | `python certify.py` | 16-gate Pre-Kali certification pipeline |
| `run_causal_validation_arena.py` | `python run_causal_validation_arena.py` | Causal validation arena benchmark |
