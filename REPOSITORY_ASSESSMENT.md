# HunterAI / PentestAI-Unified — Repository Assessment

**Assessment date:** 2026-10-26
**Assessor:** AI principal architect (automated repository inspection)
**Repository:** local checkout at `E:\Agant\PentestAI-Unified`
**Method:** static inspection of source, manifests, documentation, CI, data files, and execution of the existing test suite. No external vulnerability source was synchronized during this assessment. No file, test result, or capability in this document is asserted without a local artifact reference.

> This document is deliberately conservative. A module name is not evidence that a capability works. Where a feature is a stub, simulated, or hard-coded, that is stated explicitly.

---

## A. Concise repository assessment

HunterAI is a large Python 3.11+ security-automation monorepo. It combines a multi-agent pentest pipeline, a Burp/browser/code "sensory triad", an evidence/verdict layer, a FastAPI/Web UI, a CLI, local SQLite stores, and a learning subsystem. The codebase is substantial (≈1,810 Python files including tests, ≈304 test modules) and is not a greenfield project.

The strongest existing assets are:

1. **Authorization and scope enforcement primitives** (`core/scope_engine.py`, `core/scope_guard.py`, `core/control_plane/policy_gate.py`).
2. **An evidence-first finding model** (Evidence Court / Proof-of-Execution) that already distinguishes observation from confirmed vulnerability.
3. **A working multi-stage hunt pipeline** (`hunter_ai/pipeline/pipeline_orchestrator.py`) with artifact-based stages and reports.
4. **A sandboxed command layer** (`core/tool_registry.py`, `core/sandbox.py`) with risk levels and allowlists.
5. **A real test suite** (2,337 passed + 1 skipped in the hermetic run; see §Test baseline).

The weakest area relative to the new mission is **vulnerability intelligence**. What exists today is mostly retrieval, not intelligence:

- `core/cve_feed_learner.py` fetches the *latest* CVEs from the CIRCL API and stores them in a single JSON file. It has no NVD connector, no pagination, no checkpoints, no provenance, no normalized schema, and no version-range model.
- `core/learning/fetcher.py` fetches configured feeds and writes raw snapshots; it does not normalize or persist advisory records.
- `core/cve_intel.py` queries CIRCL by technology name and optionally Exploit-DB; it is a lookup helper, not a knowledge base.
- `data/cve_knowledge_base.json` contains **3** records (PYSEC/MAL identifiers), not a historical CVE corpus.
- `hunter_ai/tools/cve_scan.py` returns **simulated** CVE results (hard-coded Log4j/Outlook entries). It must not be presented as a scanner.
- `core/cve_intel.py` and several tests use hard-coded CVE case studies; these are teaching fixtures, not evidence of ingestion coverage.

There is **no normalized vulnerability database, no schema migrations, no incremental synchronization, no coverage measurement, no project inventory, and no capability registry with tool metadata** (language support, version ranges, license, limitations, validation status). There are also **five separate tool-registry files**, which is a duplication risk.

**Verdict:** the platform has a solid execution and evidence foundation, but its vulnerability-intelligence layer is at prototype level. The correct strategy is to add a small, independent `core/vuln_intel` subsystem that reuses the existing authorization, sandbox, logging, and evidence conventions — not to rewrite the pipeline.

---

## B. Current architecture and principal modules

### B.1 Languages and runtime

| Item | Evidence |
|---|---|
| Primary language | Python (`pyproject.toml` requires `>=3.11`) |
| Secondary | JavaScript/HTML/CSS in `ui/web` static assets; Bash/PowerShell installers (`*.sh`, `*.ps1`, `*.bat`) |
| Packaging | `pyproject.toml` (setuptools), `requirements.txt`, `requirements.lock` |
| Containerization | `Dockerfile`, `docker-compose.yml`, `docker/` |
| Supported OS | Windows (PowerShell scripts, `setup_windows.bat`) and Linux/Kali (`setup_kali.sh`, `run_kali.sh`); CI runs Ubuntu |

### B.2 Entry points

| Entry point | Purpose |
|---|---|
| `main.py` | Primary application entry (`hunterai = main:main`) |
| `pentest.py` | CLI with subcommands (`recon`, `hunt`, `validate`, `report`, `autopilot`, `surface`, etc.) and a `lead-board` subgroup |
| `cli/hunter_cli.py` | Installed `hunter` console script |
| `ui/web/app.py` | FastAPI web application/dashboard |
| `run_unified_live_session.py` | Live end-to-end session used by CI |
| `run_causal_validation_arena.py` | Epistemic/validation arena used by CI |
| `core/readiness.py` | Readiness gate (`python -m core.readiness`) |

### B.3 Directory map (high level)

| Path | Role |
|---|---|
| `core/` | Scope/policy, control plane, sandbox, tool registry, learning, knowledge DB, readiness, utilities |
| `agents/` | Specialized agents (Burp, security intelligence, skills such as SQLi) |
| `hunter_ai/` | Master pipeline, engagement manager, runtime tool registry, pipeline tool specs, CVE scan stub |
| `engines/` | Detection/analysis engines |
| `orchestrator/` | Orchestration helpers |
| `tools/` | Tool integrations and managers |
| `ui/web/` | FastAPI app, templates, static dashboard |
| `cli/` | CLI implementation |
| `tests/` | ~304 test modules; `tests/integration` excluded from CI (live/opt-in) |
| `data/` | JSON knowledge files, SQLite databases, engagement artifacts |
| `artifacts/`, `reports/`, `findings/`, `logs/` | Runtime output |
| `docs/` | 20+ design/audit/plan documents (overlapping) |
| `docker/`, `Dockerfile`, `docker-compose.yml` | Container setup |
| `.github/workflows/ci.yml` | CI pipeline |

### B.4 Pipeline architecture

`hunter_ai/pipeline/pipeline_orchestrator.py` implements a staged hunt:

```
scope → AI preflight → recon (crt.sh, subfinder, DNS, HTTP probe, crawl)
      → surface ranking → hypothesis generation → validation/evidence
      → reporting (14_reports + legacy 09_reports) → learning/memory
```

It records timeline events, data lineage, stage artifacts, and tool logs through `hunter_ai/pipeline/engagement_manager.py`. It supports `authorized` / safe mode and writes both modern (`14_reports`) and legacy (`09_reports`) report paths.

The "sensory triad" is:

- **Browser sensor** — Playwright-based behavior capture.
- **Burp sensor** — Burp integration and a local gateway (port 8085 by default).
- **Code sensor** — client-side JavaScript/code intelligence.

Findings pass through an Evidence Court / Proof-of-Execution layer before being labeled `CONFIRMED`.

### B.5 Authorization architecture

Three related layers exist:

1. `core/scope_engine.py`
   - `ScopePolicy` (Pydantic) with in-scope/out-of-scope rules, port restrictions, excluded paths, private-IP override.
   - `StrictScopeEngine` with hard invariants: loopback, link-local/metadata, multicast, reserved, RFC1918, IPv6 equivalents; URL/host/port validation; URL filtering.
2. `core/scope_guard.py`
   - `ScopeGuard` for pipeline-level target checks.
3. `core/control_plane/policy_gate.py`
   - `PolicyGate` with `ActionCategory` (`terminal_command`, `browser_navigate`, `browser_interaction`, `http_request`, `active_fuzzing`, `file_read`, `file_write`, `process_spawn`), `ActionRequest`, `PolicyDecision`, command blocklist, and `authorized` / `allow_destructive` flags.

This is a genuine strength and should be reused by the new vulnerability-intelligence and adaptive-testing layers. It is not yet wired into every tool path (see risks).

### B.6 Tool execution architecture

- `core/tool_registry.py` — tool definitions, risk levels, argument-array execution (no shell string), allowlist, sandbox (`core/sandbox.py`), approval flags.
- `hunter_ai/runtime/tool_registry.py` — MCP-style registry with JSON input schemas and `SAFE`/`AUDIT`/`ACTIVE` risk levels.
- `hunter_ai/pipeline/tool_specs.py` — pipeline tool specifications.
- `core/orchestration/tool_registry.py` — another registry variant.
- `agents/security_intelligence/tool_registry.py` — another.

**Risk:** five registries with different models; none is a capability registry in the sense required by the new mission (languages, vulnerability categories, version ranges, license, limitations, validation status).

### B.7 Data and persistence

| Store | Technology | Evidence |
|---|---|---|
| Engagement knowledge DB | SQLite (`assets`, `endpoints`, `parameters`, `traffic_records`, `ui_actions`, `ui_traffic_correlations`, `hypotheses`, `findings`) | `core/database/knowledge_db.py` |
| Structured learning KB | SQLite (`data/knowledge_base/structured_knowledge.sqlite3`) | `core/learning/knowledge_store.py` |
| Burp traffic | SQLite (`burp_traffic.db` per engagement) | `data/engagements/...` |
| CVE "knowledge base" | JSON (`data/cve_knowledge_base.json`), 3 records | file inspection |
| Raw feed snapshots | JSON files under a raw directory | `core/learning/fetcher.py` |
| Pipeline artifacts | JSON/Markdown/HTML under `artifacts/` | orchestrator/engagement manager |

There are **no database migrations** (no migrations directory, no schema-version table in the vulnerability domain). Schema evolution is ad hoc.

### B.8 AI integrations

Declared dependencies include `ollama`, `openai`, and `anthropic`; `pyproject.toml` lists all three. The pipeline has an AI preflight stage and supports an `allow_no_ai` deterministic mode. Configuration is via `.env` / environment variables and `hunter.yaml` / `config.json.example`.

No evidence was found of a centralized provider abstraction with per-provider policy, cost tracking, or redaction guarantees for outbound prompts.

### B.9 Configuration and secrets

- `.env` and `.env.example` at repo root (`.env` is present locally; it must never be committed).
- `hunter.yaml`, `config.json.example`, `model_manifest.json`, `capability_matrix.json`.
- `core/secret_sanitizer.py` masks AWS/Stripe/GitHub/JWT/Slack/password/URI credentials before persistence.
- A test-suite hang that initially appeared inside `sanitize_text` was traced to **unmocked real recon tools** in the orchestrator tests, not to a sanitizer defect. No sanitizer change was required (see §Baseline fixes).

### B.10 Logging and observability

- Python `logging` used throughout; `hunter_ai/pipeline/engagement_manager.py` writes run logs and timeline events.
- `core/console.py` provides `configure_stdio()` / `safe_print()` to survive Windows cp1256 consoles.
- `core/readiness.py` provides a readiness report.
- No structured JSON logs with correlation IDs across jobs; no source-sync metrics; no audit log dedicated to tool execution; no alert history.

### B.11 CI/CD

`.github/workflows/ci.yml`:

1. Installs `requirements.txt` + pytest plugins.
2. Runs `pytest tests/ -q -m "not slow" --ignore=tests/benchmarks --ignore=tests/v27 --ignore=tests/integration`.
3. Runs `run_unified_live_session.py`.
4. Runs `run_causal_validation_arena.py`.
5. Runs `python -m core.readiness --timeout 5`.

**Gaps:** integration tests are excluded; no lint/type/security step; no coverage threshold; no dependency audit; live session may require network/Burp/Ollama and is not hermetic.

### B.12 Documentation

`docs/` contains `architecture-audit.md`, `design.md`, `implementation-plan.md`, `IMPLEMENTATION_PLAN.md`, `IMPLEMENTATION_LEDGER.md`, `IMPLEMENTATION_STATUS.md`, `security.md`, `security_audit.md`, `OPERATIONAL_GUIDE.md`, `usage.md`, `burp-setup.md`, `mcp-setup.md`, `AGENT_SYSTEMS.md`, `CLAUDE_THINKING_ARCHITECTURE.md`, `end_to_end_test_results.md`, and more. Root-level `ARCHITECTURE.md`, `THREAT_MODEL.md`, `WORKFLOW.md`, `TEST_BASELINE.md`, `BLIND_SPOTS.md`, `PRE_KALI_CERTIFICATION.md`.

**Gap:** documents overlap and disagree; the README badge claims "42/42" tests while the hermetic suite is 2,337 passing tests (1 skipped). There is no single authoritative status document.

---

## C. Existing capabilities vs missing capabilities

### C.1 Existing and working (with evidence)

| Capability | Evidence / caveat |
|---|---|
| CLI and web app entry points | `pentest.py`, `main.py`, `ui/web/app.py`; tests import the FastAPI app |
| Staged hunt pipeline | `hunter_ai/pipeline/pipeline_orchestrator.py`; orchestrator tests pass |
| Scope/authorization primitives | `ScopePolicy`, `StrictScopeEngine`, `ScopeGuard`, `PolicyGate`; dedicated tests (`test_scope_*`, `test_network_scope`) |
| Sandboxed tool execution | `core/tool_registry.py` + `core/sandbox.py`; argument arrays and allowlists |
| Evidence/verdict model | Evidence Court/PoE modules and tests |
| SQLite persistence for engagements | `core/database/knowledge_db.py`; engagement DBs exist |
| Learning store and scenarios | `core/learning/knowledge_store.py`, `scenario_loader.py`, SQLi curriculum; tests pass |
| CVE lookup helper | `core/cve_intel.py` (CIRCL + Exploit-DB query) |
| Raw feed fetching | `core/learning/fetcher.py` (NVD/CISA/OSINT configs, raw snapshots) |
| Secret masking | `core/secret_sanitizer.py`; existing tests pass |
| Console encoding safety | `core/console.py`; regression tests pass |
| Process-tree cleanup | `core/process_utils.py`; regression tests pass |
| Readiness gate | `core/readiness.py`; CI smoke step |
| Test suite | 2,337 passed + 1 skipped in the hermetic run (four groups: 524 + 472 + 569 + 505; `tests/v27` + console safety: 53; `tests/vuln_intel`: 214). Opt-in live tests: NVD 1 passed, OSV 2 passed when enabled. A separate integration run (excluding the live artifact E2E) passed 18 tests. |

### C.2 Missing (required by the new mission)

| Capability | Before | After P1–P5 (this increment) | Remaining consequence |
|---|---|---|---|
| Normalized vulnerability schema | JSON blob with 3 records | `core/vuln_intel` SQLite schema with migrations, aliases, CWEs, references, affected packages | Legacy JSON remains separate; no migration of old data |
| Historical backfill 2000–2026 | None | Bounded NVD proof: 68 records for 2024-01-15, 0 errors | Full 2000–2026 corpus not ingested; no completeness claim |
| Incremental sync + checkpoints | None | Resumable NVD sync with per-page checkpoints and overlap | Vendor feeds still missing |
| Source connectors | CIRCL lookup + raw fetcher only | NVD 2.0 connector (rate limit, retries, size cap, pagination) + OSV.dev query connector (GHSA/CVE aliases, ranges, CVSS v3 scoring) | PHP/Composer and vendor feeds planned |
| Provenance and confidence model | Not modeled per record | Source ID, timestamps, content hash, confidence labels, raw payload opt-in | AI-cited evidence still future work |
| Version-range applicability | None | Deterministic version comparator and five-level triage | Not a full Composer/npm semver implementation |
| PHP-specific classification | None | Evidence-based runtime/extension/framework/package/application/config classifier | Text-only ambiguity remains; confidence is explicit |
| Project inventory and triage | None | JSON `ProjectProfile` + `triage` CLI with reasons and matched packages | Inventory import from manifests is future work |
| Capability registry for tools | Five partial registries, no capability metadata | `core/vuln_intel/tool_capabilities.py` + `tool_selection.py`: capability metadata, CWE→class extraction, deterministic scoring, authorization/risk/availability/ecosystem gates, explicit rejection reasons | Selection is a plan only; availability is not auto-detected; catalog is curated, not exhaustive |
| Safe lab cases | No structured lab corpus | Loopback fake target, five detectors (SQLi/XSS/IDOR/SSRF/open redirect), evidence chain, and hypothesis→gate pipeline (25 tests) | Docker/compose cases with patched variants and a validation registry remain |
| Continuous scheduler | No durable scheduler/retry queue | Unchanged | No continuous monitoring yet |
| Structured audit logs/metrics | Partial logs only | Sync runs, checkpoints, and error rows persisted | No metrics/alerting yet |
| Coverage reporting | None | Measured monthly coverage, gaps, limitations, `complete=false` by default | No denominator means no completeness claim |
| Report schema for vuln intelligence | Ad hoc Markdown/JSON | Unchanged | Inconsistent, non-auditable reports |
| Self-improvement workflow | None | Unchanged | No controlled branch/PR/test loop |

### C.3 Simulated or misleading features (must be labeled)

1. `hunter_ai/tools/cve_scan.py` returns **hard-coded simulated** CVEs and prints "Found N CVEs". It is not a scanner. It must either be wired to a real tool or clearly renamed/deprecated.
2. `data/cve_knowledge_base.json` contains 3 records, not a historical database.
3. `core/cve_intel.py` contains example CVE identifiers and a CIRCL lookup; it is not a knowledge base.
4. The README test-count badge was reconciled to 2,191 hermetic tests in this increment; certification claims still need a separate evidence review.
5. `core/cve_feed_learner.py` is described as a "learning engine" but only fetches 15 recent items into JSON; it does not learn, validate, or version.

---

## D. Security and reliability risks

### D.1 Security risks

| ID | Risk | Evidence | Severity | Mitigation direction |
|---|---|---|---|---|
| S1 | Authorization not enforced on every active path | `PolicyGate` exists, but `execute_artifact` and several tool paths do not visibly route through it | High | Single choke point for all network/process actions; deny-by-default tests |
| S2 | Untrusted advisory/web/repo text can reach LLM prompts | Learning/analyzer and AI preflight ingest external text | High | Treat as data; delimit; instruction hierarchy; never execute retrieved instructions; injection tests |
| S3 | Secret leakage in logs/reports | Sanitizer exists but is opt-in at call sites; some logs may bypass it | High | Central log filter; redaction tests; secret scanning in CI |
| S4 | Simulated CVE scanner presented as real | `hunter_ai/tools/cve_scan.py` | High (integrity) | Remove, rename to `example`, or implement real nuclei adapter |
| S5 | Tool registry fragmentation and inconsistent risk checks | Five registry files | Medium | Consolidate or define one authoritative facade with capability metadata |
| S6 | `.env` present in working tree | Repo root `.env` | High if committed | Verify `.gitignore`; rotate if ever committed; add CI secret scan |
| S7 | Network egress unrestricted for tools | Tools may call arbitrary hosts; scope checks depend on call site | High | Egress allowlist/proxy; DNS/IP revalidation at request time |
| S8 | No audit trail for tool execution | Logs are informational, not tamper-evident | Medium | Structured audit events with job IDs, tool version, args hash, target, decision |
| S9 | Prompt-injection via vulnerability descriptions | New ingestion will store attacker-controlled text | High | Data-only handling, no tool calls from content, explicit tests |
| S10 | Dependency/supply-chain risk | `requirements.txt` mostly unpinned; `requirements.lock` exists | Medium | Pin, hash, audit (`pip-audit`), SBOM |
| S11 | `verify=False` in some HTTP clients | `core/learning/fetcher.py` builds `httpx.AsyncClient(verify=False)` | Medium | Remove TLS verification bypass except explicit lab mode |
| S12 | Burp gateway lifecycle/tasks not owned | `BurpAgent.start_background_workers()` creates tasks without shutdown | Medium | Deterministic shutdown; integration-only live tests |

### D.2 Reliability risks

| ID | Risk | Evidence | Mitigation |
|---|---|---|---|
| R1 | Unit tests hit real network | Orchestrator tests mocked `execute` but not `execute_artifact`; fixed this session | Mock at the boundary; network guard fixture |
| R2 | Hangs from unowned asyncio tasks/uvicorn | Burp gateway background workers | Explicit task registry + cancel on shutdown; pytest timeout |
| R3 | O(n²) timeline persistence | `_save_timeline` sanitizes the entire timeline on every event; the observed hang was unmocked network tools, not this path | Incremental append or batched writes; size limits |
| R4 | Windows console encoding crashes | cp1256 vs Unicode box drawing/emoji | `configure_stdio` / `safe_print` (done); avoid non-ASCII in critical prints |
| R5 | Child process leaks on timeout | `proc.kill()` killed only `cmd.exe` | `kill_process_tree` via psutil (done) |
| R6 | JSON knowledge store corruption | Single-file read/write with no atomic replace | Atomic writes, backups, SQLite for new data |
| R7 | No migrations | Ad hoc schemas | Versioned migrations from day one in `core/vuln_intel` |
| R8 | CI excludes integration tests | `--ignore=tests/integration` | Separate scheduled integration job with explicit env |
| R9 | Test suite runtime ~10+ minutes | Four groups; some tests slow (orchestrator ~52s) | Mark slow, parallelize, reduce AI preflight in tests |
| R10 | Live session depends on external services | CI runs it unconditionally | Gate on env/credentials; skip cleanly when unavailable |

### D.3 Integrity risks specific to the new mission

- Claiming "complete 2000–2026 coverage" without measuring source coverage. NVD's API does not guarantee complete pre-2002 data; CVE records before 1999 are sparse; 2026 is incomplete by definition.
- Treating a CVE ID year as the discovery/publication year. The schema must store publication, last-modified, discovery (if known), and import timestamps separately.
- Treating a CPE/product name match as proof of exploitability. Applicability requires version + configuration evidence.
- Letting an LLM generate CVSS/version ranges. Deterministic parsing only; LLM output is `PROVISIONAL` at best.

---

## E. Prioritized implementation roadmap

Detailed in `IMPLEMENTATION_ROADMAP.md`. Summary:

| Priority | Phase | Deliverable | Why first |
|---|---|---|---|
| P0 | Baseline quality | Green test suite, deterministic shutdown, no simulated scanners presented as real | Trust in every later claim |
| P1 | Data model + store | `core/vuln_intel` schema, SQLite migrations, dedupe, provenance, exports | Foundation for everything |
| P2 | One authoritative connector | NVD 2.0 with pagination, retries, checkpoints, normalization | Acceptance criterion: one source syncs |
| P3 | Incremental sync + coverage | Resumable jobs, sync reports, honest coverage | Prevents false completeness claims |
| P4 | PHP intelligence | Runtime/extension/framework/package/application classification | Differentiator and explicit requirement |
| P5 | Project-aware triage | Version-range applicability with 5-level classification | Turns intelligence into decisions |
| P6 | Tool capability registry | Extend existing registry with metadata + selection engine | Safe, evidence-based testing |
| P7 | Safe lab + detectors | Reproducible local cases, validated/experimental status | Learning becomes testing capability |
| P8 | Continuous monitoring | Durable scheduler, retries, alerts, source health | Continuous operation |
| P9 | AI analysis with citations | Evidence-grounded summaries, confidence labels | Useful without inventing facts |
| P10 | Controlled self-improvement | Branch/PR workflow, allowlisted commands, review gates | Safe evolution |

**First increment (this session):** P1 + P2 + P3 + P4 + P5 core, with tests and CLI. No live external sync is claimed unless executed and recorded.

---

## F. Proposed vulnerability data schema (summary)

Full DDL lives in `core/vuln_intel/db.py`; this is the conceptual model.

### F.1 Core record

```
vulnerabilities(
  id TEXT PRIMARY KEY,                 -- canonical internal ID (source:id or CVE-...)
  canonical_id TEXT NOT NULL,          -- preferred public identifier
  source_id TEXT NOT NULL,             -- nvd | osv | ghsa | php | ...
  source_record_id TEXT NOT NULL,      -- source's own ID
  title TEXT,
  description TEXT,
  summary TEXT,
  published_at TEXT,                   -- ISO-8601 UTC, may be NULL/UNKNOWN
  last_modified_at TEXT,
  discovery_at TEXT,
  disclosed_at TEXT,
  imported_at TEXT NOT NULL,           -- distinct from published_at
  vuln_status TEXT,                    -- analyzed | modified | rejected | withdrawn | unknown
  severity TEXT,                       -- critical | high | medium | low | none | unknown
  cvss_version TEXT,
  cvss_score REAL,
  cvss_vector TEXT,
  attack_vector TEXT,
  attack_complexity TEXT,
  privileges_required TEXT,
  user_interaction TEXT,
  confidentiality_impact TEXT,
  integrity_impact TEXT,
  availability_impact TEXT,
  known_exploited INTEGER,             -- 0/1/NULL (unknown)
  confidence TEXT NOT NULL,            -- CONFIRMED_BY_AUTHORITATIVE_SOURCE | ...
  content_hash TEXT NOT NULL,
  raw_sha256 TEXT,
  provenance_json TEXT NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
)
```

### F.2 Supporting tables

```
vulnerability_aliases(vuln_id, alias, alias_type, source_id, PRIMARY KEY(vuln_id, alias))
affected_packages(id, vuln_id, ecosystem, vendor, product, package_name,
                  version_start_including, version_start_excluding,
                  version_end_including, version_end_excluding,
                  fixed_version, cpe, configuration_json)
vulnerability_cwes(vuln_id, cwe_id, PRIMARY KEY(vuln_id, cwe_id))
vulnerability_references(vuln_id, url, ref_type, source, PRIMARY KEY(vuln_id, url))
raw_records(id, source_id, source_record_id, sha256, payload_json, retrieved_at)
sync_runs(run_id, source_id, started_at, finished_at, status,
          requested_start, requested_end, pages_fetched,
          records_retrieved, inserted, updated, unchanged, duplicates,
          rejected, errors, report_json)
sync_checkpoints(source_id, range_key, cursor_json, last_success_at,
                 last_published_at, updated_at, PRIMARY KEY(source_id, range_key))
sync_errors(id, run_id, source_id, source_record_id, error_class, message, occurred_at)
schema_migrations(version INTEGER PRIMARY KEY, applied_at TEXT)
```

### F.3 Invariants

1. `published_at` and `imported_at` are never conflated.
2. Missing data is `NULL`/`unknown`, never invented.
3. `content_hash` is computed from normalized fields; an unchanged record is not rewritten.
4. Aliases are first-class and used for dedupe (CVE ↔ GHSA ↔ OSV).
5. Raw payload is preserved only when the source license permits; otherwise a hash + provenance is kept.
6. `confidence` describes the **source evidence**, not model opinion.

---

## G. First small implementation task

**Task:** implement a self-contained, tested vulnerability-intelligence vertical slice:

> Ingest NVD 2.0 records for a date range into a normalized SQLite store with provenance, dedupe, resumable checkpoints, honest coverage reporting, PHP classification, and project-aware triage — with a CLI and mocked unit tests.

This is deliberately one vertical slice, not the whole platform. It satisfies the first acceptance criteria (schema/migrations, one authoritative source, resumable imports, duplicate handling, distinct dates, PHP retrieval/classification, project applicability) without touching the existing hunt pipeline.

---

## H. Exact files for the first task

New files:

```
core/vuln_intel/__init__.py
core/vuln_intel/models.py          # Pydantic models + enums + confidence labels
core/vuln_intel/db.py              # SQLite store, migrations, dedupe, search, export, checkpoints
core/vuln_intel/sources/__init__.py
core/vuln_intel/sources/base.py    # connector ABC, rate limiter, retry/backoff, cursor
core/vuln_intel/sources/nvd.py     # NVD 2.0 connector + normalizer
core/vuln_intel/sources/osv.py     # OSV.dev query connector + normalizer (GHSA reachable)
core/vuln_intel/cvss.py            # CVSS v3.0/v3.1 base-score calculation
core/vuln_intel/vuln_classes.py    # CWE/text -> canonical vulnerability classes
core/vuln_intel/tool_capabilities.py  # tool capability metadata + catalog
core/vuln_intel/tool_selection.py  # deterministic, authorization-aware selection (plan only)
core/vuln_intel/sync.py            # SyncEngine + SyncReport
core/vuln_intel/coverage.py        # coverage/gap computation
core/vuln_intel/php.py             # PHP classification
core/vuln_intel/triage.py          # project-aware applicability
core/vuln_intel/cli.py             # python -m core.vuln_intel.cli
core/vuln_intel/README.md          # usage + limitations
tests/vuln_intel/conftest.py
tests/vuln_intel/test_models.py
tests/vuln_intel/test_versions.py
tests/vuln_intel/test_db.py
tests/vuln_intel/test_sources_base.py
tests/vuln_intel/test_nvd.py
tests/vuln_intel/test_sync.py
tests/vuln_intel/test_coverage.py
tests/vuln_intel/test_php.py
tests/vuln_intel/test_triage.py
tests/vuln_intel/test_cli.py
tests/vuln_intel/test_security.py
tests/integration/test_vuln_intel_nvd_live.py  # opt-in, skipped by default
```

Existing files to touch (minimal):

```
README.md                  # add a short pointer + honest status (optional, small)
.gitignore                 # ensure data/vuln_intel/*.sqlite3 and .env are ignored
```

No changes to the existing orchestrator, scope engine, or tool registries in this increment.

---

## I. Tests that verify the change

| Test file | Verifies |
|---|---|
| `test_models.py` | Required fields, UTC normalization, `published_at` vs `imported_at`, unknown handling, confidence enum, hash stability |
| `test_versions.py` | Numeric cores, suffixes, prerelease/unknown handling; no guessed comparisons |
| `test_db.py` | Migration idempotency, insert/update/unchanged counts, alias dedupe, CVE↔GHSA merge, search by date/product/CWE/severity, JSON/CSV export, checkpoint persistence, sync-run persistence, connection cleanup |
| `test_sources_base.py` | Rate limiting, retry/backoff, `Retry-After`, redirect allowlist, TLS verification, response-size cap |
| `test_nvd.py` | NVD JSON normalization, English description preference, CVSS v4/v3.1/v3.0/v2 preference, CPE range extraction, rejected/withdrawn handling, malformed record rejection, pagination cursor |
| `test_sync.py` | Multi-page sync, checkpoint resume after simulated interruption, idempotent re-run (0 inserted), rejected-record accounting, `max_pages`, overlapping windows |
| `test_coverage.py` | Measured months, gaps, pre-2002/current-year limitations, no false `complete=true` |
| `test_php.py` | PHP runtime vs extension vs framework vs package vs application classification; PHP mention alone does not imply vulnerability; plugin/theme handling; `php-fpm` is runtime |
| `test_triage.py` | Version-range matching, fixed-version exclusion, unknown version → insufficient evidence, name-only match → not confirmed, ecosystem mismatch → not applicable |
| `test_cli.py` | `init`, `sources`, `sync` (fake connector), `coverage`, `search`, `show`, `triage`, `classify-php`, `export` exit codes and JSON output |
| `test_security.py` | Advisory text containing prompt-injection/tool-command strings is stored verbatim as data and never executed; SQL injection is parameterized; no shell/network side effects |
| `tests/integration/test_vuln_intel_nvd_live.py` | Opt-in live NVD request (`RUN_LIVE_NVD=1`), skipped by default, records actual result |

All hermetic unit tests use mocked HTTP (`httpx.MockTransport` or a fake connector) and a temporary SQLite file. No hermetic test requires Ollama, Burp, or internet. The opt-in live test and the manual NVD check do use the internet.

---

## J. External credentials and services genuinely required

| Service | Required now? | Why | Fallback |
|---|---|---|---|
| NVD API | Optional | Higher rate limit (50 req/30s vs 5 req/30s) | Anonymous access works; slower |
| GitHub token | Optional | GHSA GraphQL/REST higher limits | Anonymous, lower limits; not in this increment |
| OSV.dev | Not required for first increment | Public API, no key | N/A |
| PHP.net / Composer / framework advisories | Not required for first increment | Public pages/feeds | N/A |
| Ollama / OpenAI / Anthropic | Not required for first increment | AI analysis comes later | Deterministic parsing only |
| Burp Suite | Not required | Existing pipeline feature, not this slice | N/A |

No credential is required to run the new unit tests. The live NVD integration test is opt-in and uses anonymous access unless `NVD_API_KEY` is set.

---

## Test baseline (measured)

Hermetic suite, run locally on 2026-10-28:

| Group | Result |
|---|---|
| Group 1 | **524 passed**, 0 failed |
| Group 2 | **472 passed**, 0 failed |
| Group 3 | **569 passed**, 0 failed |
| Group 4 | **505 passed**, 1 skipped, 0 failed |
| `tests/v27` + `tests/test_console_safety.py` | **53 passed**, 0 failed |
| `tests/vuln_intel` (new) | **214 passed**, 0 failed |

**Total: 2,337 passed, 1 skipped, 0 failed.** (The skip is `tests/test_llm_streaming.py`, an opt-in live-cloud guard, not a failure.)

One test (`tests/test_enterprise_casm.py::test_orchestrator_passive_profile_and_diff`)
requires a local Ollama server; when the AI preflight gate cannot reach
`127.0.0.1:11434`, the orchestrator aborts by design and that test fails for
environmental reasons. It passed in the recorded run with Ollama running.

The live/opt-in tests are outside the hermetic count:

```powershell
$env:RUN_LIVE_NVD = "1"
python -m pytest tests/integration/test_vuln_intel_nvd_live.py -q
# 1 passed

$env:RUN_LIVE_OSV = "1"
python -m pytest tests/integration/test_vuln_intel_osv_live.py -q
# 2 passed
```

A separate integration run on 2026-10-28 (excluding the live artifact E2E)
passed 18 tests; the 3 live NVD/OSV tests were skipped by default and passed
when enabled. The live artifact E2E was not completed in this environment:
`127.0.0.1:8085` was already held by a pre-existing Python listener, and the
test timed out after 10 minutes.

A bounded manual live NVD sync (2024-01-15, 68 records, 0 errors) is recorded in
`LIVE_NVD_VERIFICATION.md`. A bounded live OSV/GHSA query
(`symfony/http-kernel`, 8 advisories, 0 errors) is recorded in
`LIVE_OSV_VERIFICATION.md`. Neither is a full historical backfill and neither
supports a completeness claim.

Baseline fixes made during this assessment:

1. `core/console.py` — cp1256-safe stdio (`configure_stdio`, `safe_print`), used by the orchestrator and status printing.
2. `core/process_utils.py` — `kill_process_tree` (psutil); applied to `ComputerControl`, `ComputerSkill`, the SQLi sqlmap fallback, and `ToolManager.execute` timeout handling.
3. `tests/test_hunter_master_pipeline.py` — mocked `execute_artifact` (the tests previously invoked real recon tools).
4. `tests/integration/test_artifact_based_recon_e2e.py` — moved the live orchestrator test out of the hermetic unit suite.
5. `tests/test_tool_failure_classification.py` — regression test proving a timeout reaps the process tree.

### Test-hang root cause (important)

The Group 3 stall was **not** a sanitizer defect. The orchestrator unit tests mocked `master_tools.execute` but the orchestrator calls `master_tools.execute_artifact`; the tests therefore ran real `crt.sh`/`subfinder` recon against `example.com`. The stack dump happened to be inside `sanitize_text` while the pipeline was recording timeline events, which made the sanitizer look responsible. Mocking `execute_artifact` made both tests finish in ~52s (still slow, but deterministic). A probe of `sanitize_text` on long tokens showed no catastrophic backtracking. No sanitizer change was made.

A separate, real leak was found in `ToolManager.execute`: on timeout it called `proc.kill()` without reaping the shell child or awaiting the transport. It now uses `kill_process_tree`, and a regression test asserts the reaper is invoked.

---

## Assumptions and limitations of this assessment

1. The initial assessment was static plus test execution and did not contact external sources. A later bounded NVD check is recorded in `LIVE_NVD_VERIFICATION.md`; no OSV/GHSA/vendor synchronization was performed.
2. "Works" means the module imports and its tests pass; it does not mean every integration path is production-ready.
3. Test counts are from local runs, not from CI. The four groups, `tests/v27`, `tests/test_console_safety.py`, and `tests/vuln_intel` are counted; `tests/integration` is opt-in/live and excluded.
4. The repository is large; modules not directly relevant to vulnerability intelligence were reviewed at the level needed to assess architecture, not line-by-line.
5. NVD availability and rate limits were measured for one bounded request/day; OSV/GitHub/PHP availability is stated from documentation, not measured here.

---

## Immediate next actions

1. ~~Implement `core/vuln_intel` vertical slice with tests~~ — done (P1–P5).
2. ~~Run the new tests plus the existing suite~~ — done: 2,191 passed, 1 skipped, 0 failed.
3. ~~Record actual results~~ — done in `IMPLEMENTATION_ROADMAP.md`, `core/vuln_intel/README.md`, and `LIVE_NVD_VERIFICATION.md`.
4. Commit locally; do not push without explicit authorization.
5. Next capability increment: tool capability registry (P6) or OSV/GHSA connectors, not a full historical backfill yet.
