# HunterAI — Implementation Roadmap

**Date:** 2026-10-26
**Basis:** `REPOSITORY_ASSESSMENT.md` + `ARCHITECTURE_PROPOSAL.md`
**Rule:** each phase ends with tests, a status note, and a reviewable diff. No phase is "done" because code exists.

---

## 0. Status legend

| Symbol | Meaning |
|---|---|
| ✅ | Implemented and verified locally (tests/commands recorded) |
| 🟡 | Partially implemented; limitations documented |
| ⬜ | Not started |
| ⛔ | Blocked / requires owner decision or credentials |

---

## 1. Phase overview

| Phase | Name | Priority | Status | Evidence |
|---|---|---|---|---|
| P0 | Baseline quality & trust | P0 | 🟡 | Hermetic suite: 2,271 passed, 1 skipped, 0 failed; remaining P0 items listed below |
| P1 | Vulnerability data model + store | P1 | ✅ | `core/vuln_intel/{models,db}.py`; vuln_intel suite: 214 tests green |
| P2 | Historical ingestion (NVD first) | P1 | ✅ | `sources/nvd.py`, `sync.py`, `cli.py`; live one-day NVD check: 68 records, 0 errors |
| P2b | OSV/GHSA query connector | P1 | ✅ | `sources/osv.py`; live package query: 8 advisories, 0 errors; GHSA→CVE alias merge |
| P3 | Incremental sync + coverage | P1 | ✅ | `coverage.py`; measured gaps/limitations; `complete=false` by default |
| P4 | PHP intelligence | P2 | ✅ | `php.py`; evidence + confidence; plugin/theme and `php-fpm` tests |
| P5 | Project-aware triage | P2 | ✅ | `triage.py`; five-level applicability; fixed-version and unknown-version tests |
| P6 | Tool capability registry + selection | P2 | ✅ | `tool_capabilities.py`, `tool_selection.py`, `vuln_classes.py`; authorization/risk/availability/ecosystem gates; plan only |
| P7 | Safe lab + detectors | P3 | ⬜ | — |
| P8 | Continuous monitoring scheduler | P3 | ⬜ | — |
| P9 | AI analysis with citations | P3 | ⬜ | — |
| P10 | Controlled self-improvement | P4 | ⬜ | — |
| P11 | Production readiness | P4 | ⬜ | — |

---

## P0 — Baseline quality & trust

### Objectives

- The suite runs deterministically; no unit test touches the internet.
- No process leaks; no hangs.
- Simulated features are clearly labeled.
- Console output never crashes on cp1256.
- Claims in docs match reality.

### Completed

1. **Console safety** — `core/console.py` (`configure_stdio`, `safe_print`); orchestrator uses it; `tests/test_console_safety.py` (3 tests) passes.
2. **Process-tree cleanup** — `core/process_utils.kill_process_tree`; applied to `ComputerControl.execute_command`, `ComputerSkill.run_process`, and the SQLi sqlmap fallback; regression test proves the child does not survive a timeout.
3. **Hermetic orchestrator tests** — `tests/test_hunter_master_pipeline.py` now mocks `execute_artifact` (previously invoked real crt.sh/subfinder).
4. **Live test separation** — `tests/integration/test_artifact_based_recon_e2e.py` holds the live orchestrator test; CI already ignores `tests/integration`.
5. **ToolManager timeout reaping** — the timeout path now uses `kill_process_tree` and awaits the transport; regression test asserts the reaper is invoked.
6. **Test grouping** — four groups of ~63 files; Group 1 = 524, Group 2 = 437, Group 3 = 569, Group 4 = 474 passed + 1 skipped; plus `tests/v27` + console safety (53) and `tests/vuln_intel` (214); **2,271 passed, 1 skipped, 0 failed**. The opt-in live NVD test (1 passed) and OSV test (2 passed) ran separately with `RUN_LIVE_NVD=1` / `RUN_LIVE_OSV=1`.
7. **Test-hang diagnosis** — Group 3's stall was unmocked `execute_artifact` (real crt.sh/subfinder), not the secret sanitizer; the test now mocks the boundary.

### Remaining

- Label `hunter_ai/tools/cve_scan.py` as simulated (or replace with a real adapter).
- Remove `verify=False` from external fetch clients except explicit lab mode.
- Add a pytest network guard fixture for unit tests.
- CI: add lint/type/security steps; split integration job.
- Reconcile README badges with actual test counts.

### Acceptance

- Full local suite green.
- `grep` shows no unit test performing real external calls (except marked integration).
- No leaked child processes after a timeout test.
- README does not claim unimplemented capabilities.

---

## P1 — Vulnerability data model + store

**Status:** ✅ implemented and tested in this increment.

### Deliverables

- `core/vuln_intel/models.py`: `VulnerabilityRecord`, `AffectedPackage`, `CvssData`, `Reference`, `SyncReport`, `CoverageReport`, `ProjectProfile`, `TriageResult`; enums for confidence, severity, ecosystem, PHP component, applicability.
- `core/vuln_intel/db.py`: SQLite store with:
  - `schema_migrations` + `PRAGMA user_version`
  - tables: `vulnerabilities`, `vulnerability_aliases`, `affected_packages`, `vulnerability_cwes`, `vulnerability_references`, `raw_records`, `sync_runs`, `sync_checkpoints`, `sync_errors`
  - WAL, foreign keys, indexes
  - `upsert_vulnerability()` → inserted/updated/unchanged + duplicate detection
  - alias-aware merge
  - `search()`, `get()`, `export_json()`, `export_csv()`
  - checkpoint get/set
  - sync run persistence
- Migration v1 idempotent; reopening the DB does not re-apply destructively.

### Tests

- Migration idempotency.
- Insert → update → unchanged counts.
- Alias dedupe (CVE ↔ GHSA ↔ OSV).
- `published_at` ≠ `imported_at` invariant.
- Search by date/product/package/CWE/severity.
- Export JSON/CSV.
- Checkpoint persistence.
- Sync run accounting.
- Malformed record rejection without partial writes.

### Acceptance

- All P1 tests pass on a temporary DB.
- No schema change requires manual SQL.
- A repeated upsert of the same record reports `unchanged`, not `updated`.

---

## P2 — Historical ingestion (NVD first)

**Status:** ✅ implemented and tested in this increment. Live check: one NVD day,
68 records, 0 errors; see `LIVE_NVD_VERIFICATION.md`.

### Deliverables

- `core/vuln_intel/sources/base.py`:
  - `SourceMetadata` (id, name, base URL, license, terms URL, rate limit, supports date range, historical start, notes)
  - async rate limiter
  - retry with exponential backoff + jitter, `Retry-After` support, max attempts
  - HTTP wrapper: timeout, max response bytes, user agent, no `verify=False`
  - `Cursor` (startIndex/page/token), `SourceConnector` ABC
- `core/vuln_intel/sources/nvd.py`:
  - NVD 2.0 `/rest/json/cves/2.0`
  - `pubStartDate`/`pubEndDate`, `startIndex`, `resultsPerPage` (≤2000)
  - optional `apiKey`
  - rate limits: anonymous 5 req/30s, keyed 50 req/30s (configurable)
  - pagination until `startIndex + resultsPerPage >= totalResults`
  - normalization: identifiers, descriptions (English preferred), CVSS preference (v4 > v3.1 > v3.0 > v2), CWE, references, CPE configurations and version ranges, rejected/withdrawn status
  - provenance: source URL, retrieval timestamp, raw hash
- `core/vuln_intel/sync.py`:
  - `SyncEngine.run(start, end, resume=True, max_pages=None, page_size=2000)`
  - per-page transaction + checkpoint
  - report: retrieved/inserted/updated/unchanged/duplicates/rejected/errors, pages, duration, status
  - idempotent re-run
  - graceful stop on interrupt; checkpoint remains usable
- `core/vuln_intel/cli.py`:
  - `sync --start ... --end ... --db ... [--max-pages N] [--page-size N] [--no-resume]`
  - `coverage`, `search`, `show`, `export`

### Tests

- NVD fixture normalization (multiple CVSS versions, CPE ranges, rejected record).
- Pagination across 3 pages.
- Retry on 429/500 then success.
- Resume after simulated interruption at page 2 → starts at page 2, no duplicates.
- Re-run → 0 inserted, all unchanged.
- Malformed record → rejected + error row, other records persist.
- Rate limiter respects interval (fake clock).
- Response size cap.

### Acceptance

- A fake NVD server (mocked transport) syncs a multi-page range end-to-end.
- Interrupted sync resumes from the checkpoint.
- Re-running is idempotent.
- Report counts add up exactly.
- No live network in unit tests.

### Live verification (optional)

- `tests/integration/test_vuln_intel_nvd_live.py`, skipped unless `RUN_LIVE_NVD=1`.
- If run, record actual HTTP status, record count, date range, and elapsed time in the final report. **Do not claim success without the artifact.**
- Result on 2026-10-26: `RUN_LIVE_NVD=1` → 1 passed. Manual one-day sync → 68 records, 0 errors; see `LIVE_NVD_VERIFICATION.md`.

---

## P2b — OSV/GHSA query connector

**Status:** ✅ implemented and tested. Live package query: 8 advisories, 0 errors;
see `LIVE_OSV_VERIFICATION.md`.

### Why a separate path

OSV has **no date-range pagination API**. Forcing it into `SyncEngine` would mean
inventing a window the API does not support. The connector is therefore
query-based (`POST /v1/query`, `GET /v1/vulns/{id}`) and is deliberately excluded
from the date-window sync flow (`fetch_page()` refuses with a clear error).

GHSA is reachable through OSV: GitHub advisories are mirrored in OSV, so a GHSA
id, its CVE alias, affected packages, ranges, and severity are all available. A
direct GitHub GraphQL connector remains future work.

### Deliverables

- `core/vuln_intel/sources/base.py`: `HttpClient.post_json()` sharing the same
  retry / redirect-allowlist / size-cap envelope as `get_json()`.
- `core/vuln_intel/sources/osv.py`:
  - `OSV_METADATA` (`source_id="osv"`, `supports_incremental=False`,
    `max_window_days=0`, host allowlist `api.osv.dev`);
  - `OSVConnector.query_package(name, ecosystem, version=None)` and `get_vuln(id)`;
  - `normalize_osv_record()`:
    - CVE alias becomes the canonical id, the OSV/GHSA id stays an alias, so an
      OSV record merges with the same CVE from NVD instead of duplicating it;
    - `ranges` (`introduced` / `fixed` / `last_affected` / `limit`) → version
      ranges; `"0"` means "all versions"; `fixed` also populates `fixed_version`;
    - exact `versions[]` used only when no usable range exists;
    - `GIT` ranges are **never** turned into version ranges (kept in metadata);
    - CWEs read from `database_specific` and `ecosystem_specific` (top-level and
      per-affected);
    - CVSS v3 vectors are scored locally by `core/vuln_intel/cvss.py` (CVSS v4
      vectors are stored but not scored);
    - `withdrawn` → `WITHDRAWN`.
- `core/vuln_intel/cvss.py`: CVSS v3.0/v3.1 base score (spec Appendix A) with
  known-vector tests; never guesses.
- CLI: `osv-query`, `osv-get` (optional `--db`, `--store-raw`, `--json`).
- `sources` now lists both NVD and OSV.

### Tests

- GHSA→CVE canonical/alias merge and dedupe against an NVD record.
- Range parsing (`introduced`/`fixed`/`last_affected`/open-ended/`"0"`).
- Exact-version fallback; GIT ranges ignored as version ranges.
- CWE extraction from `database_specific` + `ecosystem_specific`.
- CVSS v3 scoring (known vectors) and v4 non-scoring.
- Withdrawn records; missing id; non-object payloads.
- Mocked POST body/URL; `fetch_page()` refusal.
- CLI `osv-query` / `osv-get` with an injected fake connector (no network).

### Live verification (optional)

- `tests/integration/test_vuln_intel_osv_live.py`, skipped unless `RUN_LIVE_OSV=1`.
- Result on 2026-10-27: `RUN_LIVE_OSV=1` → 2 passed. Manual package query
  (`symfony/http-kernel`, Packagist) → 8 advisories stored, 0 errors; triage and
  tool selection exercised on the stored records. See `LIVE_OSV_VERIFICATION.md`.

---

## P3 — Incremental sync + coverage

**Status:** ✅ implemented and tested in this increment.

### Deliverables

- Checkpoint keyed by `(source_id, range_key)` where `range_key` is `historical:<start>:<end>` or `incremental`.
- Incremental window: last successful `published_at` minus overlap (default 2 days), capped by now.
- `coverage.py`:
  - months requested vs months with ≥1 record, per source
  - gaps list
  - source limitations (e.g., NVD pre-2002 sparsity, 2026 incomplete)
  - explicit `complete=false` unless measured against a defined denominator
- Sync report persisted and exportable.

### Tests

- Incremental window computation (overlap, cap, no future dates).
- Coverage with a deliberate gap.
- Coverage never returns `complete=true` without a denominator.
- 2026 is labeled in-progress.

### Acceptance

- Coverage output states: source, requested range, measured range, records, months covered, gaps, limitations, `complete` flag.
- No text claims "all vulnerabilities" without a measured denominator.

---

## P4 — PHP intelligence

**Status:** ✅ implemented and tested in this increment.

### Deliverables

- `core/vuln_intel/php.py`:
  - `classify_php(record) -> PhpAnalysis`
  - component types: `RUNTIME`, `EXTENSION`, `FRAMEWORK`, `PACKAGE`, `APPLICATION`, `SERVER_CONFIG`, `UNKNOWN`
  - frameworks/packages: Laravel, Symfony, WordPress, Drupal, Magento/Adobe Commerce, Composer packages (`vendor/name`)
  - evidence list (CPE vendor/product, package ecosystem, CWE, description keywords as supporting only)
  - `involves_php` + confidence
  - rule: PHP mention alone ≠ vulnerable
- Integration into `triage.py` and reports.

### Tests

- PHP core CVE → RUNTIME.
- PHP extension CVE → EXTENSION.
- Laravel/Symfony/WordPress/Drupal/Magento → FRAMEWORK.
- Composer package → PACKAGE.
- Generic PHP app CWE → APPLICATION.
- Non-PHP advisory → `involves_php=False`.
- "Built with PHP" alone → not vulnerable / insufficient evidence.

### Acceptance

- Every classification includes evidence and confidence.
- No classification is based solely on the word "PHP" in a description.

---

## P5 — Project-aware triage

**Status:** ✅ implemented and tested in this increment.

### Deliverables

- `ProjectProfile` (project id, name, ecosystem, packages with versions, PHP version, frameworks, manifests, last scan).
- `triage.py`:
  - ecosystem + package name match (normalized, case-insensitive where appropriate)
  - version range evaluation (including/excluding, fixed version)
  - installed version unknown → `INSUFFICIENT_EVIDENCE` or `POSSIBLY_APPLICABLE` (never confirmed)
  - name-only match → not confirmed
  - fixed version installed → `NOT_APPLICABLE` with evidence
  - classifications: `CONFIRMED_APPLICABLE`, `LIKELY_APPLICABLE`, `POSSIBLY_APPLICABLE`, `NOT_APPLICABLE`, `INSUFFICIENT_EVIDENCE`
- CLI: `triage --project project.json --vuln CVE-...` / `--all`.

### Tests

- In-range → confirmed/likely.
- Out-of-range → not applicable.
- At fixed version → not applicable.
- Unknown version → insufficient evidence.
- Wrong ecosystem → not applicable.
- Name match only → not confirmed.
- Pre-release handling.
- Multiple affected ranges.

### Acceptance

- No finding is silently discarded; uncertain results are reported with reasons.
- Version comparison is deterministic and unit-tested.

---

## P6 — Tool capability registry + selection

**Status:** implemented (`core/vuln_intel/tool_capabilities.py`, `tool_selection.py`, `vuln_classes.py`).

### Delivered

- `ToolCapability` metadata model: languages, ecosystems, vulnerability classes, input/output types, risk level, availability (`installed` / `not_installed` / `unknown`), authorization requirement, active/passive flag, reliability, test coverage, permissions, constraints, limitations, license, last validated.
- Built-in catalog of 9 tools with **honest** metadata: every entry ships `availability=unknown` and `last_validated=None`, because this repository never verified the binaries.
- `select_tools(record, project, scope, capabilities)` — deterministic scoring with explicit rejection reasons:
  - vulnerability class from CWE (primary) + explicit advisory phrases (supporting) via `classify_vuln_classes`;
  - authorization gate: active tools are rejected unless the scope is explicitly authorized;
  - risk ceiling gate (`low` / `medium` / `high` / `critical`);
  - availability gate: an unverified binary is rejected unless the caller relaxes it;
  - ecosystem match (agnostic tools are not blocked);
  - input-type match;
  - reliability / test-coverage bonus;
  - stable tie-break by `tool_id`.
- `NOT_APPLICABLE` triage results block selection entirely (no theoretical hunting).
- CLI: `select-tools` (plan only, never executes).
- No automatic installation; no tool execution anywhere in the selection path (enforced by a test that monkeypatches `subprocess`).

### Deliberate deviation

`core/tool_registry.ToolDefinition` was **not** modified. The working tree already
contains in-flight changes to that module, and capability metadata is a
vulnerability-intelligence concern. `capability_from_tool_definition()` adapts the
existing registry instead, so the two layers can converge later without a merge
conflict.

### Tests

- No tool selected for an unsupported category (`insufficient_evidence`).
- Active tool not selected without authorization.
- Missing/unverified binary → not selected, with reason.
- Risk above the granted ceiling → rejected.
- Ecosystem mismatch → rejected.
- Allowlist enforcement.
- `NOT_APPLICABLE` advisory → nothing selected.
- Deterministic ordering, including ties.
- Popularity alone cannot win (no popularity input exists).
- Selection never executes a tool.

### Acceptance

- Every selection has a documented reason and evidence. ✅
- No automatic installation. ✅

---

## P7 — Safe lab + detectors

### Deliverables

- `lab/cases/<case>/case.yaml`, compose/Dockerfile, fixtures, expected observations, patched variant, cleanup.
- Runner with network disabled by default, non-root, resource limits, no host mounts.
- Detector status: `EXPERIMENTAL` / `VALIDATED` with evidence.
- Positive + negative fixtures; false-positive measurement where possible.

### Tests

- Lab config validation.
- Network-disabled default.
- No privileged mode / host mount.
- Vulnerable fixture → detected; patched fixture → not detected.
- Experimental detectors cannot be marked validated without evidence.

### Acceptance

- At least one end-to-end lab case with vulnerable + patched verification.
- Detector registry records limitations and last validation.

---

## P8 — Continuous monitoring scheduler

### Deliverables

- Durable job table (`sync_jobs`) with states: queued/running/succeeded/failed/dead.
- Worker with bounded concurrency, retries, exponential backoff, jitter.
- Source health metrics, last success, lag, error classes.
- Alert hook (log/webhook), alert history.
- Graceful shutdown and resume.
- Configurable intervals; NVD default 6h incremental.

### Tests

- Duplicate enqueue is idempotent.
- Worker retry then success.
- Dead-letter after max attempts.
- Interrupted job resumes.
- Health report reflects failures.

### Acceptance

- Kill the worker mid-job → restart resumes without duplicates.
- Failed source produces actionable log with class and next retry.

---

## P9 — AI analysis with citations

### Deliverables

- Retrieval over the store (structured filters + optional FTS).
- Prompt builder with untrusted-content delimiters.
- Output schema requiring citations.
- Confidence labels; unsupported claims rejected/downgraded.
- Separate storage for AI analyses; invalidation when source changes.

### Tests

- Prompt injection in description does not alter instructions or trigger tools.
- Missing citation → validation failure.
- Contradictory evidence → `CONTRADICTED_BY_EVIDENCE`.
- Re-evaluation flag on source update.

### Acceptance

- Every AI claim maps to a stored source reference.
- No tool execution is derived from retrieved text.

---

## P10 — Controlled self-improvement

### Deliverables

- Branch-per-change workflow; diff review; test/lint/security gates.
- Allowlisted command runner (argument validation, timeouts, output limits, restricted FS).
- Human approval gates for authorization, credentials, network exposure, exploit functionality, auto-execution, deletion, destructive migrations, production deploy.
- PR generation (optional, requires token).

### Tests

- Disallowed command rejected.
- Change touching protected paths requires approval.
- Branch isolation; no direct main writes.
- Test failure blocks merge proposal.

### Acceptance

- A sample improvement is produced on a branch with tests and a review summary.
- No automatic merge/deploy.

---

## P11 — Production readiness

### Deliverables

- Structured logs + correlation IDs.
- Metrics/health endpoints.
- Backup/restore drill.
- Config validation at startup.
- Secrets management and redaction audit.
- Performance baseline (sync throughput, DB size, query latency).
- Documentation: install, configure, test, recover, disclose.

### Acceptance

- Restore from backup verified.
- Health check detects a broken DB.
- No secrets in logs (automated scan).
- Runbook tested.

---

## 2. This session's plan (time-boxed)

| Step | Work | Verification |
|---|---|---|
| 1 | Finish Group 4 | pytest result |
| 2 | Commit baseline fixes | `git status`, `git log` |
| 3 | Write 5 assessment docs | files exist, reviewed |
| 4 | Implement P1 models + store | new tests pass |
| 5 | Implement P2 NVD connector + normalizer | mocked NVD tests pass |
| 6 | Implement P2 sync engine + checkpoints | resume/idempotency tests pass |
| 7 | Implement P3 coverage | gap/limitation tests pass |
| 8 | Implement P4 PHP classifier | classification tests pass |
| 9 | Implement P5 triage | version-range tests pass |
| 10 | Implement CLI | CLI tests pass |
| 11 | Run new tests + affected existing tests | all green |
| 12 | Optional live NVD probe | ✅ 1 passed; manual 2024-01-15 sync: 68 records, 0 errors |
| 13 | Update docs with actual results | ✅ counts and limits updated |
| 14 | Commit | local only (pending final review) |

All hermetic steps are complete: **2,271 passed, 1 skipped, 0 failed**. The
integration directory remains opt-in/live; the orchestrator live test is not
part of the hermetic count.

### Explicit non-goals this session

- No live exploitation.
- No tool installation.
- No OSV/GHSA connectors (next increment).
- No scheduler, lab, AI analysis, or self-improvement.
- No changes to the hunt pipeline behavior.

---

## 3. Definition of done (per phase)

A phase is done only when:

1. Code is implemented and imports cleanly.
2. Unit tests cover happy path, edge cases, and failure modes.
3. The new tests pass locally.
4. Existing tests in the affected area pass.
5. Limitations and unsupported cases are documented.
6. No secrets, no real credentials, no simulated success.
7. The diff is reviewable and scoped.
8. Status is updated in this roadmap.

---

## 4. Risks and mitigations (roadmap level)

| Risk | Impact | Mitigation |
|---|---|---|
| Scope creep into exploitation | Safety/legal | Explicit non-goals; policy gate; no exploit generation |
| NVD rate limits / API changes | Ingestion stalls | Backoff, checkpoints, fixture-based tests, source health |
| License restrictions on raw data | Legal | Store normalized + hash by default; per-source policy |
| False completeness claims | Integrity | Coverage requires denominator; `complete=false` default |
| LLM hallucination | Wrong findings | Deterministic parsing; citations; confidence labels |
| Test suite slowdown | Developer velocity | Mark slow/integration; mock boundaries; parallel groups |
| Tool registry fragmentation | Inconsistent safety | Consolidation plan (P6) |
| Windows encoding | Crashes | `safe_print`; ASCII-critical output |
| Data loss | Rework | WAL, atomic transactions, backups, migrations |

---

## 5. Owner decisions needed (non-blocking)

1. Raw payload storage policy per source.
2. Retention periods.
3. AI provider allowed to process untrusted advisory text (default: local Ollama only).
4. Whether GitHub write operations (branches/PRs) are authorized; token scope.
5. Whether to consolidate the five tool registries now or after P5.
6. Production database target (SQLite vs PostgreSQL) and deployment environment.

Defaults are implemented so work can proceed without answers; changing a default later is a configuration change, not a rewrite.
