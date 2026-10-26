# HunterAI — Architecture Proposal

**Status:** proposal, grounded in the actual repository
**Date:** 2026-10-26
**Scope:** vulnerability intelligence, adaptive authorized testing, and safe capability development
**Constraint:** extend the existing architecture; do not replace it

---

## 1. Design principles

1. **Evidence before claims.** Every record, finding, and tool result carries provenance, timestamps, and a confidence label. Model output is never a source of fact.
2. **Deterministic where correctness matters.** Parsing, version comparison, identifier normalization, dedupe, and schema validation are code — not LLM calls.
3. **Untrusted by default.** Advisory text, web pages, repository files, and PoCs are data. They never become instructions or executable commands.
4. **Deny by default for active actions.** No network/process action without an explicit, unexpired authorization scope and a policy decision.
5. **One vertical slice at a time.** Each phase ships with tests and a status report; no giant unreviewable change.
6. **No duplicate subsystems.** New code either extends an existing module or lives in a clearly bounded package with an explicit integration contract.
7. **Honest coverage.** The system reports what it measured, from which source, for which date range, with gaps — never "all CVEs".
8. **Reversible changes.** Versioned migrations, atomic writes, backups, and feature flags for anything that touches existing behavior.

---

## 2. Target logical architecture

```
┌────────────────────────────────────────────────────────────────────────────┐
│                         Presentation / Interfaces                          │
│  CLI (pentest.py, core.vuln_intel.cli)   Web UI (ui/web/app.py)   Reports  │
└───────────────────────────────┬────────────────────────────────────────────┘
                                │
┌───────────────────────────────▼────────────────────────────────────────────┐
│                      Orchestration & Scheduling                            │
│  existing hunt pipeline (hunter_ai/pipeline)   new sync scheduler          │
│  job IDs, retries, checkpoints, graceful shutdown, audit events            │
└───────────────┬───────────────────────────────┬────────────────────────────┘
                │                               │
┌───────────────▼───────────────┐ ┌─────────────▼──────────────────────────────┐
│  Vulnerability Intelligence   │ │  Adaptive Testing (authorized only)        │
│  (new: core/vuln_intel)       │ │  (extends existing pipeline + policy gate) │
│                               │ │                                            │
│  connectors → normalizer      │ │  target profile → applicability            │
│  → dedupe/upsert → SQLite     │ │  → test planner → policy gate → executor   │
│  → coverage → PHP classifier  │ │  → evidence collector → report             │
│  → triage → search/export     │ │  → capability feedback                     │
└───────────────┬───────────────┘ └─────────────┬──────────────────────────────┘
                │                               │
┌───────────────▼───────────────────────────────▼────────────────────────────┐
│                     Shared Foundations (existing, reused)                  │
│  ScopePolicy / StrictScopeEngine / PolicyGate  (authorization)             │
│  core/tool_registry + core/sandbox             (execution + allowlists)    │
│  core/secret_sanitizer + core/console          (safe output)               │
│  core/process_utils                            (timeouts, tree kill)       │
│  core/database/knowledge_db (engagement DB)    (findings, evidence)        │
│  core/readiness                                (health gate)               │
└────────────────────────────────────────────────────────────────────────────┘
                                │
┌───────────────────────────────▼────────────────────────────────────────────┐
│                            Persistence                                     │
│  SQLite: vuln_intel.sqlite3 (new, source of truth for advisories)          │
│  SQLite: engagement DBs (findings/evidence)                                │
│  JSON: raw source snapshots (license-permitting) + hashes                  │
│  Optional FTS5 index for search (no vector DB until measured benefit)      │
└────────────────────────────────────────────────────────────────────────────┘
```

---

## 3. New package: `core/vuln_intel`

### 3.1 Why a new package (and why it is not duplication)

Existing modules are **retrieval helpers** (`core/cve_feed_learner.py`, `core/learning/fetcher.py`, `core/cve_intel.py`). None provides a normalized, versioned, deduplicated advisory store. Creating a bounded package avoids destabilizing them. The old modules remain usable; the new package becomes the authoritative advisory store. A later, small adapter can make `CVEFeedLearner` read from `core/vuln_intel` instead of JSON.

### 3.2 Module responsibilities

| Module | Responsibility | Must not do |
|---|---|---|
| `models.py` | Pydantic models, enums, confidence labels, validation | Perform I/O |
| `db.py` | SQLite schema/migrations, transactions, upsert, dedupe, search, export, checkpoints | Call external APIs |
| `sources/base.py` | Connector ABC, rate limiter, retry/backoff, cursor, response-size limits | Know about SQLite |
| `sources/nvd.py` | NVD 2.0 pagination + normalization | Write to the DB directly |
| `sources/osv.py` (later) | OSV package/ID queries + normalization | Duplicate NVD logic |
| `sync.py` | Run a connector, validate, upsert, account, checkpoint, report | Parse source-specific JSON |
| `coverage.py` | Compute measured coverage and gaps | Claim completeness |
| `php.py` | PHP component classification from structured evidence | Label an app vulnerable from "uses PHP" |
| `triage.py` | Project inventory vs advisory version ranges | Guess versions |
| `cli.py` | User-facing commands | Bypass authorization for active actions |
| `report.py` (later) | JSON/Markdown vulnerability reports | Invent CVSS or versions |

### 3.3 Data flow (ingestion)

```
NVD API
  → connector.fetch_page(cursor)  [rate limit, retry, timeout, size cap]
  → raw page (validated shape)
  → normalizer.to_record(raw)     [deterministic mapping]
  → record validation             [required fields, date sanity, hash]
  → store.upsert(record, raw)     [alias-aware dedupe, content hash]
  → sync_run accounting           [inserted/updated/unchanged/rejected/errors]
  → checkpoint.save(cursor)       [after each successful page]
  → coverage.report()             [measured months, gaps, limitations]
```

### 3.4 Data flow (triage)

```
ProjectProfile (registered repo, manifests, versions)
  + VulnerabilityRecord (affected packages, ranges, fixes)
  → deterministic matcher (ecosystem + package + version range)
  → classification:
       CONFIRMED_APPLICABLE | LIKELY_APPLICABLE | POSSIBLY_APPLICABLE
       NOT_APPLICABLE | INSUFFICIENT_EVIDENCE
  → evidence list + reasons + confidence
  → report (never silently drop uncertain)
```

### 3.5 Integration contracts

- **Authorization:** `triage` is passive and needs no scope. Any future active validation calls `PolicyGate.evaluate()` before execution; `core/vuln_intel` must not implement its own authorization.
- **Execution:** any detector runs through the existing `core/tool_registry` / sandbox; no direct `subprocess` in the new package.
- **Evidence:** findings produced by adaptive tests are written to the existing engagement DB/evidence model, not a parallel findings store.
- **Logging:** structured events use a `job_id`; secrets pass through `SecretSanitizer`.
- **Configuration:** new settings live in `.env`/`hunter.yaml` with documented placeholders; no secrets in code.

---

## 4. Reuse map (explicit)

| Need | Reuse | Do not create |
|---|---|---|
| Scope validation | `core/scope_engine.StrictScopeEngine` | new scope parser |
| Action authorization | `core/control_plane/policy_gate.PolicyGate` | new permission system |
| Command execution | `core/tool_registry` + `core/sandbox` | direct subprocess |
| Timeouts/process cleanup | `core/process_utils` | new kill logic |
| Secret masking | `core/secret_sanitizer` | new regex set |
| Console safety | `core/console` | new print wrapper |
| Engagement findings | `core/database/knowledge_db` | parallel findings DB |
| Readiness | `core/readiness` | separate health endpoint (extend instead) |
| AI access | existing provider configuration | hard-coded model clients |
| Tool metadata | extend `core/tool_registry.ToolDefinition` with capability fields | sixth registry |

### 4.1 Tool registry consolidation direction

There are five registry files. The proposal is:

1. Keep `core/tool_registry.py` as the **authoritative execution registry** (it already has sandboxing and allowlists).
2. Add optional capability metadata to its `ToolDefinition` (languages, vuln categories, input/output, license, version, limitations, validation status, last validated).
3. Make `hunter_ai/runtime/tool_registry.py` a thin adapter/facade over the authoritative registry, not a second source of truth.
4. Deprecate the others with a documented mapping.

This is a later phase; the first increment does not touch them.

---

## 5. Database architecture

### 5.1 Source of truth

A dedicated SQLite database: `data/vuln_intel/vuln_intel.sqlite3`.

Why SQLite first:

- Zero-ops, matches the existing stack.
- ACID, WAL, FTS5 available.
- Easy backup (file copy after `PRAGMA wal_checkpoint`).
- Sufficient for millions of advisory rows with proper indexes.

Migration path to PostgreSQL is kept open by avoiding SQLite-only SQL in the domain layer (except FTS5, which is optional and isolated).

### 5.2 Schema versioning

- `schema_migrations(version, applied_at)`.
- Migrations are ordered, idempotent functions.
- `PRAGMA user_version` mirrors the latest version for quick checks.
- Backups are taken before destructive migrations (none planned in v1).

### 5.3 Idempotency and dedupe

- Canonical key: `(source_id, source_record_id)`.
- Alias table enables cross-source merge (CVE ↔ GHSA ↔ OSV).
- `content_hash` over normalized fields: unchanged records are counted but not rewritten.
- Upsert is a single transaction; a failed page does not partially persist.

### 5.4 Search

- v1: indexed SQL filters (date, product, package, ecosystem, CWE, severity, source).
- v2: FTS5 over title/summary/description, if measured to help.
- Vector search is **deferred** until a benchmark demonstrates benefit; the spec explicitly allows this.

### 5.5 Backup/recovery

- `python -m core.vuln_intel.cli backup --out <file>` (later) uses SQLite backup API.
- Documented restore procedure: stop writers, verify integrity (`PRAGMA integrity_check`), replace file, re-run coverage.

---

## 6. Continuous monitoring architecture

```
scheduler (durable)
  → enqueue sync job (source, window, checkpoint)
  → worker (bounded concurrency)
  → SyncEngine.run()
  → retry queue (exponential backoff, jitter, max attempts)
  → dead-letter table + alert
  → metrics: last_success, lag, error rate, records/min
```

Requirements:

- Idempotent jobs (same window twice → no duplicates).
- Checkpoints persisted per page.
- Overlap windows (e.g., re-fetch last 2 days) to catch late modifications; upsert handles changes.
- Source health: last success, consecutive failures, HTTP status distribution.
- No aggressive polling: interval ≥ source guidance; NVD default 6 hours for incremental, historical backfill chunked.

The first increment implements the **engine** and **checkpoint/report**; the scheduler is phase P8.

---

## 7. Adaptive testing architecture (later phases)

### 7.1 Target profile

Built from evidence:

- Authorized HTTP headers/fingerprint (passive).
- Provided source/manifests (authoritative).
- Authorized authenticated inventory (if supplied).
- Existing scan results.

Each fact carries `source`, `confidence`, `observed_at`. No fact is inferred from a product name alone.

### 7.2 Applicability engine

Reuses `triage.py`. Outputs the five-level classification. Only `CONFIRMED_APPLICABLE`/`LIKELY_APPLICABLE` are eligible for active tests; `POSSIBLY_APPLICABLE` requires more evidence or explicit human decision.

### 7.3 Test planner

Inputs: scope, applicability, capability registry, risk, prerequisites, evidence requirements.
Output: an ordered plan where every step records:

- vulnerability ID, reason, prerequisites, tool/module + version,
- expected observation, side effects, authorization requirement,
- stop conditions, evidence requirements, cleanup.

Planner rules:

1. Passive before active.
2. Version verification before payloads.
3. Static analysis before dynamic.
4. Non-destructive before intrusive.
5. No test solely because an exploit is public.
6. Smallest set that yields meaningful evidence.

### 7.4 Execution guard

Every step passes through:

1. Scope revalidation **immediately before** the request.
2. `PolicyGate.evaluate()`.
3. Egress allowlist + DNS/IP re-resolution (prevent rebinding).
4. Rate/concurrency/timeout/size limits.
5. Audit event (job, tool, args hash, target, decision, result hash).
6. Emergency stop flag checked between steps.

### 7.5 Evidence and reporting

Reuse the existing evidence model. A vulnerability report distinguishes:

- tool output (verbatim, redacted),
- deterministic interpretation (version match, config match),
- AI interpretation (labeled `PROVISIONAL` unless backed by authoritative citation),
- confirmed finding (requires adequate evidence),
- indicator / theoretical possibility.

---

## 8. Safe lab architecture (later)

- Each case is a directory with `case.yaml` (metadata), `docker-compose.yml` or Dockerfile, fixtures, expected observations, patched variant, cleanup.
- Default: no network, non-root, read-only root FS where possible, CPU/memory limits, no host mounts, no privileged mode.
- Detectors run against vulnerable and patched fixtures; results recorded with versions and timestamps.
- Capability status: `EXPERIMENTAL` until positive + negative fixtures pass and limitations are documented; `VALIDATED` only with reproducible evidence.
- If exact reproduction is unsafe, ship a conceptual demo + regression test instead.

---

## 9. AI analysis architecture (later)

- Retrieval-augmented generation over the SQLite store (structured filters first, FTS optional).
- Prompt construction separates:
  - system policy (immutable),
  - task instructions,
  - retrieved untrusted content (clearly delimited, labeled "data"),
  - output schema.
- Output must cite record IDs/URLs. Unsupported claims are rejected or downgraded.
- No tool calls generated from retrieved content. Tool selection is deterministic from the capability registry.
- Confidence labels: `CONFIRMED_BY_AUTHORITATIVE_SOURCE`, `STRONGLY_SUPPORTED`, `PROVISIONAL`, `UNVERIFIED`, `CONTRADICTED_BY_EVIDENCE`.
- Every AI analysis is stored separately from source records and marked for re-evaluation when the source changes.

---

## 10. Observability and reliability

- Structured JSON logs with `job_id`, `source_id`, `run_id`, `record_id`, `duration_ms`, `outcome`.
- Metrics: records fetched/inserted/updated/rejected, pages, retries, rate-limit waits, source lag, checkpoint age.
- Error classes: `NETWORK`, `RATE_LIMIT`, `AUTH`, `SCHEMA`, `VALIDATION`, `DB`, `INTERNAL`.
- Health checks: DB integrity, last successful sync per source, disk space, scheduler heartbeat.
- Graceful shutdown: stop fetching, finish current page transaction, persist checkpoint, close clients.
- No secrets in logs; sanitizer applied to structured fields.

---

## 11. Security boundaries

| Boundary | Control |
|---|---|
| External source → system | Untrusted data; schema validation; size limits; no execution |
| System → external source | Read-only by default; allowlisted hosts; rate limits; no auth bypass |
| AI → tools | No direct execution; deterministic planner + policy gate |
| Tools → network | Scope revalidation, egress control, rate limits |
| Tools → filesystem | Sandbox, allowlisted paths, no host mounts |
| Reports/logs → user | Secret redaction, coordinated disclosure rules |
| Self-improvement → main | Branch + PR + human review for sensitive areas |

---

## 12. What is explicitly out of scope (for now)

- Exploit generation or autonomous exploitation.
- DoS, persistence, credential theft, evasion, data exfiltration.
- Attacking arbitrary internet hosts.
- Vector search (until measured benefit).
- Full replacement of the existing orchestrator.
- Automatic installation of third-party security tools.
- Automatic merge to `main`.

---

## 13. Success criteria for the architecture

1. One advisory source syncs end-to-end with provenance and resumable checkpoints.
2. Re-running the same job creates zero duplicates and zero inconsistent state.
3. `published_at` and `imported_at` are distinct in every record.
4. A project question ("does CVE-X affect package Y version Z?") gets a deterministic, evidence-backed classification.
5. PHP findings distinguish runtime/extension/framework/package/application.
6. Unauthorized active tests are rejected by the existing policy gate, with an audit event.
7. Adversarial advisory text cannot trigger tool execution.
8. Coverage reports state measured months, sources, and gaps — never unqualified completeness.
9. Existing tests remain green.
10. Every change is reviewable as a small diff with tests.

---

## 14. Open questions / decisions to confirm with the owner

1. **License/storage:** may raw NVD/OSV payloads be stored, or only normalized records + hashes? Default: store raw only for sources whose terms permit; otherwise hash + URL.
2. **Retention:** how long to keep raw snapshots and sync reports? Default: 90 days for raw, 2 years for reports.
3. **Database location:** `data/vuln_intel/` vs a configurable path. Default: configurable, with `data/vuln_intel/` as the local default.
4. **Scheduler runtime:** in-process asyncio vs OS service. Default: in-process with a durable SQLite job table; OS service later.
5. **Tool registry consolidation:** which of the five registries is authoritative? Proposal: `core/tool_registry.py`.
6. **AI provider policy:** which provider may receive advisory text, and under what retention terms? Default: local Ollama only for untrusted content until approved.

These do not block the first increment; defaults are documented in code.
