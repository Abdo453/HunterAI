# HunterAI — Implementation Roadmap

**Branch:** `feat/platform-unification`
**Rule:** A phase is marked complete only after implementation, tests, and a tagged verification gate pass in this repository. Test counts are recorded only from executed runs and never projected ahead of verification.

---

## Status Legend

| Symbol | Meaning |
| :--- | :--- |
| ✅ | Implemented and verified at a tagged gate |
| 🔄 | In progress on current branch |
| 🟡 | Partially implemented; remaining scope documented |
| ⬜ | Planned / not started |

---

## 1. Platform Unification Track (Phases 0–8)

This is the active engineering track consolidating the Django ASGI control plane, Go ARTEX-Pro engine, Next.js Obsidian Sentinel UI, canonical runtime, Evidence Court, Sensory Triad, AI infrastructure, and CI/container hardening.

| Phase | Scope | Status | Verified Git Tag / Key Modules |
| :--- | :--- | :---: | :--- |
| **Phase 0** | Safety baseline, pinned read-only upstream clones (`external/`), isolation boundaries (`.gitignore`, `.dockerignore`, `pyproject.toml`), `NOTICE` & AGPL-3.0 ban | ✅ | `baseline/pre-unification` (`d5dd2bb6`), `phase/0-green` (`bbd3f723`); `tests/test_external_isolation.py`, [docs/MIGRATION_BASELINE.md](docs/MIGRATION_BASELINE.md) |
| **Phase 1** | Critical service-plane security hardening: Django local bearer auth, PBKDF2-SHA512 KDF, `sgn` revocation, `userTier`/`tokenTier`, CSRF/Origin/WS/CSP, non-code editor sandbox, shell-free subprocess allowlist, approval `proposal_digest`, Burp/Go/BugHunter MCP hardening | ✅ | `phase/1-green` (`76f8b9f5`); `hunter_backend/{auth,middleware,websocket}.py`, `backend/internal/api/server.go`, `tests/security/test_p1_service_hardening.py`, [docs/security.md](docs/security.md) |
| **Phase 2** | Canonical runtime orchestrator, 7-state run lifecycle (`Flow -> Task -> Subtask`), idempotency, crash recovery, unified config manager, Django/Go parity | ✅ | `phase/2-green` (`59fd1bf4`); `core/runtime/{orchestrator,state_machine,event_bus,agent_manager}.py`, `tests/test_canonical_runtime_contracts.py` |
| **Phase 3** | Authoritative 7-state Evidence Court (`UNVERIFIED`, `CANDIDATE`, `CONFIRMED`, `REJECTED`, `INCONCLUSIVE`, `UNAVAILABLE`, `ERROR`) and typed `ProofContract` / PoE truthfulness | ✅ | `phase/3-green` (`c017b8e3`); `core/evidence_court.py`, `core/poe_engine.py`, `tests/test_evidence_court_truthfulness.py` |
| **Phase 4** | Canonical tool catalog (`config/tools.catalog.yaml`, 68 tools / 13 tiers), hardened cross-platform/Docker sandbox (`core/sandbox.py`), canonical skill registry (`skills/registry.json`), dual-channel prompt templates (`core/prompts/`), 8 Apache-2.0 PentesterFlow corpora (`wordlists/pentesterflow/`), script & import hygiene | ✅ | `phase/4-green` (`0fced3af`); `core/tool_registry.py`, `scripts/sync_tool_manifests.py`, `tools/install_opencode_skills.py`, `tests/test_registry_parity.py`, `tests/test_cross_platform_sandbox.py`, `tests/test_prompt_templates.py` |
| **Phase 5** | Sensory Triad seam repair (Browser, Burp, Code Intel) and `core/vuln_intel/` runtime + `/api/vuln-intel/*` integration; non-overridable SSRF/scheme invariants | ✅ | `phase/5-6-green` (`79ce0ccf`); `core/sensors/sensory_triad.py`, `core/vuln_intel/`, `tests/test_sensory_triad_and_vuln_intel.py` |
| **Phase 6** | Canonical `LLMRouter` (`core/llm_router.py`), AST context compaction & tool offloading (`core/context/`), priority-queued `GPUScheduler` (`core/llm/gpu_scheduler.py`), fail-closed `core/security_mode.py` & Copilot `PolicyGate`, telemetry | ✅ | `phase/5-6-green` (`79ce0ccf`); `core/llm_router.py`, `core/context/`, `core/llm/gpu_scheduler.py`, `tests/test_llm_context_vram.py` |
| **Phase 7** | Unified Next.js Obsidian Sentinel dashboard (`frontend/app/`), live Copilot streaming UI, WCAG contrast & Arabic RTL hardening, frontend verification suite | ✅ | `phase/7-green` (`0111cdd2`); `frontend/`, `npm run verify:ui` |
| **Phase 8** | Release hardening: Dockerfile/Compose hardening & WAF lab `:8088` port separation, full Python/Go/Next.js CI matrix, full-platform E2E & VRAM benchmarks, verified zero-caller dead-code retirement, documentation reconciliation | 🔄 | Active on `feat/platform-unification`; final counts and pass/fail verdicts will be recorded by Phase 8 QA/Security verification runs |

---

## 2. Vulnerability Intelligence, Policy & Safe Lab Track (P0–P11)

The subsystems below were delivered prior to and integrated during platform unification. Historical pre-unification test counts are omitted in favor of running the current suites listed in [README.md](README.md#verification).

| Increment | Name | Status | Implemented Modules & Scope Notes |
| :--- | :--- | :---: | :--- |
| **P0** | Baseline quality & hermetic test discipline | ✅ | `core/console.py` (cp1256/UTF-8 safety), `core/process_utils.py` (`kill_process_tree`), live integration test isolation under `tests/integration/` |
| **P1** | Vulnerability data model + SQLite store | ✅ | `core/vuln_intel/{models,db}.py` — WAL SQLite schema, idempotent migrations, alias-aware upsert (`CVE <-> GHSA <-> OSV`), JSON/CSV export |
| **P2** | Historical ingestion (NVD 2.0) | ✅ | `core/vuln_intel/sources/{base,nvd}.py`, `sync.py`, `cli.py` — async rate limiting, retry/backoff, per-page checkpoints, opt-in live test (`RUN_LIVE_NVD=1`) |
| **P2b** | OSV / GHSA query connector | ✅ | `core/vuln_intel/sources/osv.py`, `core/vuln_intel/cvss.py` — query-based package lookup (`POST /v1/query`), local CVSS v3 scoring, opt-in live test (`RUN_LIVE_OSV=1`) |
| **P3** | Incremental sync & coverage reporting | ✅ | `core/vuln_intel/coverage.py` — gap tracking and explicit `complete=False` unless measured against a denominator |
| **P4** | PHP intelligence | ✅ | `core/vuln_intel/php.py` — evidence-backed classification across runtime, extension, framework, package, and application components |
| **P5** | Project-aware triage | ✅ | `core/vuln_intel/triage.py`, `versions.py` — deterministic version range comparison into five applicability levels |
| **P6** | Tool capability registry + selection | ✅ | `core/vuln_intel/{tool_capabilities,tool_selection,vuln_classes}.py` — plan-only selection gated by authorization, risk ceiling, availability, and ecosystem (consolidated with `config/tools.catalog.yaml` in Phase 4) |
| **P6b / P6c** | Authorized red-team policy engine & registry gate | ✅ | `core/policy/red_team.py`, `core/tool_registry.py` — HMAC-signed `AuthorizationGrant`, `safe`/`standard`/`red_team` profiles, non-overridable hard invariants, hash-chained `AuditLog` |
| **P7a / P7b / P7c** | Safe loopback lab, 5 detectors & gate pipeline | 🟡 | `core/detectors/` — read-only `HttpTransport`, boolean SQLi, reflected XSS, IDOR, loopback-canary SSRF, open-redirect detectors, `EvidenceChain`, `HypothesisPipeline`, `LabValidationGate`. Remaining: containerized vulnerable/patched lab case matrix and detector validation registry (`EXPERIMENTAL -> VALIDATED`) |
| **P8** | Continuous vulnerability monitoring scheduler | ⬜ | Durable `sync_jobs` queue, bounded-concurrency worker, source lag health metrics, alert hooks |
| **P9** | Citation-enforced AI advisory analysis | ⬜ | Structured store retrieval with mandatory source citations and contradiction checks |
| **P10** | Controlled self-improvement workflow | ⬜ | Branch-per-change patch proposals gated by allowlisted checks and human approval (no auto-merge/deploy) |
| **P11** | Multi-host production readiness | ⬜ | Correlation-ID structured logging, backup/restore drills, automated log secret scanning, load baselines |

---

## 3. Definition of Done

A phase or increment is complete only when:

1. Implementation imports cleanly across affected services without regressions.
2. Unit, security, and contract tests cover happy paths, edge cases, and failure modes.
3. All applicable verification gates (Python, Go, Next.js, manifest/skill checks) execute and pass locally or in CI.
4. Limitations, non-goals, and unverified areas are stated explicitly without fabricated numbers.
5. No hardcoded secrets, banned AGPL-3.0 dependencies (`github.com/vxcontrol/cloud`), or uncommitted upstream clones enter tracked paths.

---

## 4. Open Operational Decisions (Non-Blocking Defaults Active)

1. **Raw Advisory Retention:** Store normalized records + SHA-256 hashes by default; raw payload retention remains configurable per source.
2. **Untrusted Advisory LLM Routing:** Configure `HUNTER_LLM_POLICY=local_only` when policy prohibits sending untrusted advisory or target data to external LLM APIs.
3. **Production Database Target:** PostgreSQL (`:5432`) backs Go ARTEX-Pro; SQLite backs `PlatformStore` and `core/vuln_intel` locally until multi-node deployment requires shared PostgreSQL state.
4. **Network Exposure:** Control-plane services bind loopback by default; LAN or remote exposure requires reverse-proxy TLS termination and explicit `HUNTERAI_TRUSTED_PROXIES` configuration.
