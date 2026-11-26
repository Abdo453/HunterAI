# HunterAI / PentestAI-Unified — Controlled Implementation Plan

> **Authoritative Source:** `docs/IMPLEMENTATION_AUDIT.md` (evidence-backed live audit) + `docs/IMPLEMENTATION_LEDGER.md` (completed work).
> **Rule:** No item counts as "complete" without: implementation + actually executed tests + production-path integration. No mock/stub may mask a gap.
> **Last Updated:** 2026-10-16 (Session 3).

---

## 1. Governing Rules (Definition of Done per Phase)

1. **No `CONFIRMED` without proof:** Every path writing a confirmed status must pass through `EvidenceCourt` with re-evaluable proof (`ProofStrength.DERIVED`) or a tagged declared proof through a documented trusted gate (`DECLARED` + `allow_declared_proof`).
2. **Mandatory governance:** Every sensitive operation (tool/command/network execution) passes through `Scope Engine` + `Policy Gate` in **fail-closed** mode.
3. **Auditability:** Every execution logs `project_id`, `tool_id`, `action`, `timestamp`, authorization decision, and outcome/status.
4. **No secrets** in source, config, or audit/engagement artifacts (sanitized at all output boundaries).
5. **Backward compatibility:** No breaking public API/CLI changes without a documented reason and compatibility path.
6. **Phase cadence:** Green targeted tests → health check → `git diff` review → explanation + proposed commit message → **stop for sign-off**.
7. **Measure, don't narrate:** Whenever an issue looks "environmental/expected", re-measure directly before concluding (§8.1 of the audit).

---

## 2. Baseline (Completed Work) — Do Not Rebuild

| LEDGER | Component | Status |
|---|---|---|
| 001 | `CoverageStatus` regression | ✅ EXISTS |
| 002 | `StrictScopeEngine.from_file` | ✅ EXISTS |
| 003 | Scope ordering before AI Preflight | ✅ EXISTS |
| 004 | Close `PolicyGate` terminal-command bypass | ✅ EXISTS |
| 005 | Record tool failures as coverage gaps | ✅ EXISTS |
| 006 | Unified reasoning engine + orchestrator wiring | ✅ EXISTS |
| 007 | Derived proof across detectors and paths | ✅ EXISTS |
| 008 | Tool execution governance (`ToolManager` → `PolicyGate`) | ✅ EXISTS (missing: host allowlist) |
| 009 | Court gate on `InvestigationController` promotion | ✅ EXISTS |
| 010 | Remove dead court-bypassing promotion path | ✅ EXISTS |
| 011 | Eliminate silent `CONFIRMED` (schema + `EvidenceOS` + team reviewer) | ✅ EXISTS |

**Test baseline:** Full suite **1262/1262 passing** (13 minutes) on the reference state.

---

## 3. Audit Status Map

### P0 (Prevents a Reliable System)
| # | Item | Status |
|---|---|---|
| 1 | Court trusts caller flags | ✅ LEDGER-007 |
| 2 | Confirmation path bypasses court | ✅ LEDGER-009 |
| 3 | **Pipeline never produces a confirmed finding** | ⏳ **M1** |
| 4 | Dead verification block | ✅ LEDGER-010 |
| 5 | **PoE engine unwired** | ⏳ **M1** |
| 6 | **Two contradicting courts (V1/V2)** | ⏳ **M1** |
| 7 | Guardrail bypass via terminal commands | ✅ LEDGER-004 |
| 8 | Tool execution without policy/scope | ✅ LEDGER-008 (allowlist pending → M2) |
| 9 | Security gate runs after AI | ✅ LEDGER-003 |
| 10 | **Non-air-gapped environment + Gemini key** | 🔒 **Owner decision** |
| 11 | Broken CLI | ✅ LEDGER-001 |
| 12 | `--scope-file` crashes pipeline | ✅ LEDGER-002 |
| 13 | **Three parallel contracts** | ⏳ **M3** |
| 14 | **No shared investigation state (6 stores)** | ⏳ **M3** |
| 15 | **Unsanitized secret leaks into artifacts** | ⏳ **M2** |
| 16 | Tool failures silently swallowed | ✅ LEDGER-005 |
| 17 | Dangerous defaults | ✅ LEDGER-011 |

### P1 (Prevents Genuine Collaboration)
Remaining: **18–27, 29–34, 36** (distributed across M1–M5). Partially done: nothing fully closed here yet.

### P2 (Hygiene and Consistency)
Remaining: **37–44** (distributed across M0 and M6).

---

## 4. Controlled Phases

| Phase | Objective | Items | Depends On | LEDGER |
|---|---|---|---|---|
| **M0** | Quick baseline hardening | P2:44,40,43,41 | — | 012 ✅ Done |
| **M1** | Permanently close verification loophole | P0:3,5,6 · C2,C3,C4,C5 | M0 | 013–016 |
| **M2** | Unified governance & scope + secret redaction | P0:8,15 · P1:35,36 | M1 | 017–019 |
| **M3** | Contracts + shared state | P0:13,14 · P1:29,31 · M8 | M2 | 026–028 |
| **M4** | Agents, teams, and scheduling (real collaboration) | P0:scheduler · P1:18–20,24–27 | M3 | 029–032 |
| **M5** | Real results (producing findings) | P0:3 completion · P1:32,33,34 · P2:42 | M4 | 033–035 |
| **M6** | Test coverage + hygiene + documentation | P2:37,38,39 · missing gates | M5 | 036–038 |

> **Numbering note (2026-10-17):** IDs `LEDGER-020…025` were allocated to the owner-requested model/UI track (unified router + Claude-style UI + streaming + cloud preflight gate), recorded in `docs/IMPLEMENTATION_LEDGER.md`. Consequently, later phases in this plan were shifted by +6: **M3** (`026–028`) · **M4** (`029–032`) · **M5** (`033–035`) · **M6** (`036–038`).

---

### M0 — Quick Baseline Hardening (LEDGER-012) ✅ Done

**Objective:** Fix small, high-impact bugs before larger structural changes.

| Item | Location | Action | Acceptance |
|---|---|---|---|
| P2-44 | `core/tool_registry.py:211` | Import `Tuple` (or remove usage) | Calling the function raises no `NameError` + test |
| P2-40 | `config/settings.yaml:28-33` | Remove/harden unread `unrestricted_scope` and `auto_approve_all` or wire to a fail-closed gate | No unread "open-by-default" setting |
| P2-43 | Zero-byte/duplicate files | Delete empty `nvidia_test.py` and remove duplicate re-export in `core/terminal_bridge.py` | Clean `git grep` |
| P2-41 | Hardcoded Ollama host `192.168.1.3` in 6 locations | Unify into a single config source defaulting to `127.0.0.1` | Single source + test |

**Risk:** Very low. **Rollback:** Isolate each change.

---

### M1 — Permanently Close Verification Loophole (LEDGER-013…016) — Top Priority

**Objective:** No production path may assert confirmation without re-evaluable proof, and the pipeline must produce confirmed findings **honestly** when a real vulnerability exists.

**Execution order within M1 (ascending risk, descending dependencies):**
`M1a = 013` → `M1b = 014` → `M1c = 015` → `M1d = 016`.
Each sub-phase has an independent test suite + sign-off stop. Rationale: 016 is isolated; 014 lays the foundation for 015/013; 013 delivers the final guarantee on top of unified adjudication.

**M1a — LEDGER-013: Prevent Direct Writes (C7)**
- Actual locations:
  - `core/arbitration_engine.py:79` — `is_verified = tool_output.get("verified", False) or tool_output.get("objective_met", False)` then `stage = CONFIRMED` (line 82). Risk: raw tool flag → confirmation.
  - `core/confidence_checker.py:474-522` `_calculate_consensus` — model voting produces `CONFIRMED` without derived proof.
- Action: Any path to `LifecycleStage.CONFIRMED` / `final_verdict=CONFIRMED` must pass through a derived-proof gate (verified `ProofPayload` or court re-adjudication). Flags (`verified`, `objective_met`) become **signals**, not verdicts; at most they raise status to `UNVERIFIED`/`NEEDS_REVIEW`.
- Acceptance: Test proving `verified=True` alone never yields `CONFIRMED`; test-enforced `grep` covering all remaining `CONFIRMED` sites.

**M1b — LEDGER-014: Unify Courts V1/V2 (P0-6 / C2) — ✅ Done (tested 98/98)**
- Locations: `core/court/evidence_court_v2.py:65-165` (`adjudicate_case` takes caller `proof_nonce_proven: bool`) · caller `core/brain/autonomous_brain.py:2294-2302` computes `proof_nonce_proven` from `has_arith` (text search).
- Action: `EvidenceCourt` v1 is the sole authority. Turn V2 into a presentation facade over V1: accept `proof_payload`/`verifier_result`, delegate the ruling to `EvidenceCourt.adjudicate`, and derive `TribunalRuling` from it. V2 must **never** promote a boolean flag into proof. Without a proof payload → never `CONFIRMED`.
- Backward compatibility: Preserve `adjudicate_case` signature (boolean params) so `tests/test_v8_investigation_os.py::TestEvidenceCourtV2` and `test_v8_brain_integration.py` stay compatible, while changing semantics: flags without proof payload ⇒ `REFUTED`/`INCONCLUSIVE`. Update legacy tests that expected proof-free confirmation.
- Acceptance: Tests proving identical inputs (valid proof payload) produce the same ruling from V1 and V2, V2 without payload never confirms, and V1 and V2 never contradict each other.

**M1c — LEDGER-015: Remove Flag/Reflection Confirmations (C3/C4/C5) — ✅ Done (tested 171+107)**
- C3 (free text as proof): `core/brain/autonomous_brain.py:2263-2267` — `is_reflection = "reflection" in p_reason.lower()` and `has_arith = "72" in p_reason and "53+19" not in p_reason`. Action: no rulings from free text; rely on structured fields in `poc_result` (measured token/differential) rather than string search.
- C4 (default-true sensors): `core/brain/autonomous_brain.py:2459-2460` — `f.get("dom_executed", True)` and `f.get("diff_confirmed", True)` ⇒ `agreement_ratio=1.0`. Action: default `False` (fail-closed) + read fields from real channels.
- C5 (reflection ≠ execution): `core/scoring/tool_agreement.py:59-61` (keeps reflection refutation) · `core/smart_probe_engine.py:370,381` (`probe in probe_resp.text` ⇒ XSS) · `core/independent_verifier.py:69-72` (`"<tagxyz>123" in text` ⇒ "confirmed unsanitized reflection"). Action: reflection ≠ execution; XSS confirms only with execution proof (PoE/DOM execution), and reflection stays a hypothesis.
- Acceptance: Reflection/coincidence refutation tests + zero confirmations from free-text input or default-true sensors.

**M1d — LEDGER-016: Wire PoE and Convert Scanner Sites — ✅ Done (tested 166)**
- Locations: `hunter_ai/pipeline/pipeline_orchestrator.py` `FindingQualificationGate` call sites (`dalfox`/`nikto`/`secrets`, etc.) passing only `reproduced`.
- Action: (a) Pass real request/response data to `ProofOfExecutionEngine` / `ProofPayload` whenever proof is re-evaluable (token/arithmetic/differential/signature). (b) Anything not re-evaluable becomes a **hypothesis** feeding `InvestigationController` rather than direct confirmation.
- Acceptance: Test checking `findings_count`: 0 without proof, > 0 with valid proof payload. (Implemented in `tests/test_poe_pipeline_gate.py` + `_court_verifier_result` = `bool(directly_observed and proof_payload)` + `_defer_hypothesis` + fixed `build_standard_injection_chain` tautology.)

**Risk:** High (touches court and `autonomous_brain`). **Rollback:** Independent commits + existing evidence tests act as guardrails. No edits to `autonomous_brain` without a targeted test covering the affected path.

---

### M2 — Unified Governance & Scope + Secret Redaction (LEDGER-017…019) — ✅ Done (tested 192+)

**LEDGER-017 — Unify Scope/Policy (P1-35) — ✅**
- Four scope implementations + two classes named `PolicyEngine`, one wide-open by default (`core/gateway/policy_engine.py:33-40`).
- Action: Single reference engine (fail-closed by default) with all other wrappers delegating to it.
- Acceptance: Test asserting "open-by-default = rejected". (Implemented: `PolicyEngine(full_permissions=False)` + `_ReferenceScopeGuard` delegating to `StrictScopeEngine` + `test_scope_policy_unification.py`.)

**LEDGER-018 — Close IP Encoding Bypasses (P1-36) — ✅**
- `core/scope_engine.py:196-222` and `:311-312`: handle `127.1`, `2130706433`, `0x7f000001`, IPv6-mapped addresses.
- Acceptance: Scope invariant tests (loopback/metadata/RFC1918 + all encodings). (Implemented: `normalize_ip_literal` + 16 tested forms.)

**LEDGER-019 — Sanitize Secrets at Artifact Outputs (P0-15) — ✅**
- `pipeline_orchestrator.py:1320` → `engagement_manager.py:229,201,174`: run `secret_sanitizer` on every raw artifact write.
- Acceptance: Test verifying an injected secret never appears in plaintext in any output file. (Implemented: `EngagementManager` sanitizes all outputs + `test_artifact_secret_sanitization.py`.)

---

### M3 — Contracts and Shared State (LEDGER-026…028)

**LEDGER-026 — Unify Contracts (P0-13)**
- Standardize on `ToolExecutionResult`; make `ToolExecutionMeta` (`schemas.py:219-235`) an adapter delegating to it; wire into `MasterToolRegistry`.
- Acceptance: Single contract path + integration test.

**LEDGER-027 — Unified Shared State (P0-14 / MISSING)**
- Consolidate 6 separate stores into a single source of truth read and written by the pipeline.
- Acceptance: E2E test where one stage writes state and another reads the same state.

**LEDGER-028 — Wire Coverage and Graphs**
- Wire `CoverageLedger` into the pipeline (P1-31) · read `EvidenceGraph`, not write-only (P1-29) · remove import-time side effects (M8).

---

### M4 — Agents, Teams, and Scheduling (LEDGER-029…032)

**LEDGER-029 — Scheduler (P0 Task Scheduler / P1-21,23)**
- `core/system/task_scheduler.py`: fix self-review guard bypass; add `parameters` to `add_task`; stop `Simulated noop` from passing as success.
- Acceptance: Tests verifying self-review rejection, `parameters` propagation, and noop failure.

**LEDGER-030 — Agent Teams (P1-18,19,20)**
- Either rebuild `core/teams` on top of real `MasterToolRegistry` (real network/subprocess execution) or **delete** it in favor of real `agents/` — **owner decision**.
- Acceptance: Every team agent executes real work or is deleted (no mocks).

**LEDGER-031 — Silence Fabricated Outputs**
- `subagent_manager_v2.launch_subagent` (P1-24) · `cli/hunter_cli.py:630-632` + `ui/web/app.py:1636-1640` (P1-25) · `orchestrator_workers.py:500-552` (P1-26) · `CognitiveCouncil HEURISTIC_PASS` (P1-27).

**LEDGER-032 — Real Experience Memory (P1-30)**
- `core/orchestration/investigation_loop.py:133-186` stops unconditionally recording success.

---

### M5 — Real Results (Producing Findings) (LEDGER-033…035)

**LEDGER-033 — E2E Produces Findings**
- Finish M1 across the live path + add `findings_count` test (P2-42): `testphp.vulnweb.com` produces > 0 findings; a clean target produces 0.

**LEDGER-034 — Remove False Tool Attribution**
- `BurpRepeaterController` (P1-32) · `crtsh` false success on exit 127 (P1-33) · `httpx` credited without execution (P1-34).

**LEDGER-035 — Certification Gate Coverage**
- Ensure `certify.py` actually invokes tools (not 15/15 passing simply because tools never run).

---

### M6 — Test Coverage, Hygiene, and Documentation (LEDGER-036…038)

- **LEDGER-036:** Missing gate tests: `qualification_gate` (P0) · `task_contracts` (P0) · WAF/`BLOCKED` branch · scope invariants.
- **LEDGER-037:** Test isolation (P2-37: tests must not mutate git-tracked files).
- **LEDGER-038:** Update `docs/IMPLEMENTATION_STATUS.md` (P2-38) · resolve unread config files (P2-39).

---

## 5. Owner Decisions (Require Sign-Off Before Execution)

| # | Item | Decision Required |
|---|---|---|
| D1 | P0-10: Active Gemini key + cloud tried before local + target data sent externally | Should the system be **local-first**, using cloud only via explicit opt-in? |
| D2 | P1-18/19: `core/teams` (18 mocked agents) | Rebuild on real tools **or delete** and rely on `agents/`? |
| D3 | Missing external tools (`subfinder`/`httpx`/`nuclei`/`ffuf`/…) | Install them in the test environment or keep fallback paths only? |

---

## 6. Execution and Verification Cadence

For every phase: (1) isolated branch/change → (2) implementation → (3) targeted tests + full suite as needed → (4) health check → (5) diff review → (6) commit message → (7) **stop for sign-off**.

**Environment note:** This repository auto-commits in the current environment during work; proposed commit messages are therefore provided for documentation, and `git` status is checked before each phase to avoid mixing changes.
