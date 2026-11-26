# HunterAI — Implementation Ledger

> **Session:** 2026-10-16 · **Branch:** `main`
> **Rule:** An item is not complete just because code was written — only when acceptance criteria pass in live execution.
> **Status Codes:** `EXISTS` · `PARTIAL` · `MOCKED` · `DISCONNECTED` · `MISSING` · `UNVERIFIED` · `BLOCKED`

---

## Session Summary

| Item | Before | After | Verification |
|---|---|---|---|
| `CoverageStatus` (regression `af1af9c`) | ❌ Dead CLI + 5 collection errors + 5 failures | ✅ **EXISTS** | 32/32 passed · 68-command CLI working |
| `StrictScopeEngine.from_file` | ❌ `AttributeError` kills pipeline | ✅ **EXISTS** | Verified live (§ below) |
| Scope/AI gate ordering | ❌ AI before scope + network call before denial | ✅ **EXISTS** | Re-run: denied in 2.41s |
| `PolicyGate` terminal-command bypass | ❌ metadata/loopback allowed | ✅ **EXISTS** | 19 new regression tests |
| Tool failure recording | ❌ Swallowed at 15 call sites | ✅ **EXISTS** | 7 blindspots logged E2E |

**Test baseline (measured live in this session):**

| Stage | Collected | Passed | Failed | Collection Errors | Duration |
|---|---|---|---|---|---|
| Start of session (Ollama available) | 1064 | 1052 | 12 | 5 | 7:52 |
| After `CoverageStatus` fix | 1129 | — | — | **0** | — |
| Focused check on the 5 changes | — | **59** | 0 | 0 | 18s |
| **Full suite (final state)** | **1129** | **1156** | **0** | **0** | **4:53:26** |

> **Critical operational note:** Full-suite runtime jumped from ~8 minutes to **4 hours 53 minutes** as soon as Ollama became available. Many tests run **real local LLM inference** with no mocks and no short timeouts. Previously they failed fast at preflight, masking the cost.
> Consequence: the suite is **unusable as a CI gate** in its current form. This is a test-suite issue rather than a production bug, to be addressed in Phase 7 (reducing runtime / isolating inference behind fixtures). All numbers above are real and unshortened.

The collected count (`1129`) is lower than the passed count (`1156`) because parametrized tests expand into additional cases at execution time.

> **Important correction:** The previous audit round labeled 5 failures as "environmental" due to Ollama being down. **That classification was wrong in this session**: Ollama is online (`qwen3:8b`, `qwen2.5-coder:14b`, `qwen2.5-coder:14b-tools`, `xploiter/pentester:latest`, `WhiteRabbitNeo/Llama-3.1-WhiteRabbitNeo-2-8B:latest`) and AI Preflight passes completely (`online=True, inference_ok=True, 3/3 roles`). Re-running the failures showed that only **5** were real code bugs, all caused by one regression: `CoverageStatus`.

---

## LEDGER-001 — Fix `CoverageStatus` Regression

| Field | Value |
|---|---|
| **Capability** | Endpoint-level coverage ledger + unified CLI |
| **Previous Status** | `MISSING` (interface removed while callers still depended on it) |
| **Files Inspected** | `core/coverage/coverage_ledger.py`, `core/coverage/__init__.py`, `cli/hunter_cli.py:50,456-467,1101-1113`, `core/brain/autonomous_brain.py:1734-1736,2470-2471,2565-2566`, `tests/test_v18_...py:106-128`, `tests/test_v2_deep_architecture.py:47-64` |
| **Files Changed** | `core/coverage/coverage_ledger.py` · `core/coverage/__init__.py` |
| **Change Description** | Restored the legacy interface **inside the same class** instead of creating a parallel ledger: `CoverageStatus` (10 values), `SurfaceItem`, `record_probed()`, `record_skipped()`, `format_terminal_coverage_map()`, and the `items` field. Extended `UntestableReason` with 6 causal reasons previously lost, plus `LEGACY_STATUS_TO_REASON` mapping skip states to structured reasons. Constructor accepts both `target_scope` and `persistence_file` (detecting positional `.json` paths). `get_summary()` now returns a **merged projection**: asset-level keys (new) + endpoint-level keys (legacy) without collisions. |
| **Tests Executed** | `pytest tests/test_v18_auditable_security_platform.py tests/test_v2_deep_architecture.py tests/test_agent_teams_benchmark.py` · `pytest tests/test_autonomous_brain_state.py tests/test_integration_pipeline.py tests/test_v19_epistemic_security_os.py tests/v27/test_v27_brain_ooda_and_endpoints.py` · `pytest tests --collect-only` · `python cli/hunter_cli.py coverage --domain example.com` |
| **Test Results** | ✅ **32/32 passed** · ✅ **Collection errors 5 → 0** (1129 collected) · ✅ CLI runs and prints negative-space coverage ledger |
| **Remaining Limitations** | `/ledger` is not an argument to the `coverage` command (it uses `--domain`); pre-existing behavior left unchanged |
| **Current Status** | ✅ **EXISTS** |

---

## LEDGER-002 — `StrictScopeEngine.from_file`

| Field | Value |
|---|---|
| **Capability** | Load scope policy from file (`--scope-file` / `scope.yaml` / `scope.json`) |
| **Previous Status** | `MISSING` — `pipeline_orchestrator.py:178` called a nonexistent method ⇒ crash |
| **Files Inspected** | `core/scope_engine.py:88-146`, `hunter_ai/pipeline/pipeline_orchestrator.py:176-193`, `main.py:46,124` |
| **Files Changed** | `core/scope_engine.py` · `hunter_ai/pipeline/pipeline_orchestrator.py` |
| **Change Description** | 1) Added `from_file()` supporting YAML/JSON and nested `scope:` keys, explicitly raising `FileNotFoundError`/`ValueError` instead of falling back to a permissive policy. 2) Exposed `check_inviolable()` as a public interface for hard invariants (used in LEDGER-004). 3) Added missing `from pathlib import Path`. 4) In Orchestrator: passed `rate_limit_rps` instead of the nonexistent `max_rate_limit_rps` (which was silently dropped) and applied the scope file's declared rate limit. |
| **Tests Executed** | `python main.py -t https://evil.example.net --scope-file scratch/_scope_ok.json --dry-run --allow-no-ai` · `python main.py -t https://example.com --scope-file ...` · `pytest tests/test_policy_invariants_on_commands.py::TestScopeFileLoading` |
| **Test Results** | ✅ Out-of-scope target denied in **2.41s** with `out_of_scope` (no crash). ✅ In-scope target: `SCOPE_APPROVED → PREFLIGHT_PASSED (AI_READY) → completed`. ✅ 4/4 scope-file loading tests passed. ✅ Verified rate limit `3.5` propagated from file into `AdaptiveRateLimiter` |
| **Remaining Limitations** | No pre-construction schema validation beyond Pydantic |
| **Current Status** | ✅ **EXISTS** |

---

## LEDGER-003 — Gate Ordering: Scope Before AI Preflight

| Field | Value |
|---|---|
| **Capability** | Enforce scope before any outbound network traffic (constitutional P0 rule) |
| **Previous Status** | ❌ `MISSING` — two inverted gates |
| **Files Inspected** | `hunter_ai/pipeline/pipeline_orchestrator.py:2348-2400,516-596` · `hunter_ai/pipeline/state_machine.py:61-78` |
| **Files Changed** | `hunter_ai/pipeline/pipeline_orchestrator.py` · `hunter_ai/pipeline/state_machine.py` |
| **Change Description** | Two separate defects: **(a)** `run()` called `stage_ai_preflight()` before `stage_scope_check()`, so out-of-scope targets returned `ai_preflight_failed` instead of `out_of_scope` while AI preflight made network calls and wrote artifacts for unauthorized targets. **(b)** Inside `stage_scope_check`, `ProgramIntelligence.discover_program()` made an outbound network call **before** the rejection check at `:589`. Fix: check scope first and hard-abort on rejection before any network code. Updated the FSM transition table to allow `SCOPE_CHECK → PREFLIGHT` and `AI_READY/DEGRADED_MODE → DISCOVER` while keeping legacy transitions for backward compatibility. |
| **Tests Executed** | `pytest tests/test_hunter_master_pipeline.py tests/test_hunter_workflow_pipeline.py tests/test_enterprise_casm.py tests/test_artifact_based_recon.py tests/test_program_intelligence_and_triad.py tests/test_scope_and_false_positives.py` · E2E runs on both targets |
| **Test Results** | ✅ **44/44 passed** (0.5–5.7 min) with zero regressions. ✅ E2E: out-of-scope denied in 2.41s before any request. ✅ FSM explicitly rejected the new order on the first try — proving state transitions are genuinely enforced — before the table was intentionally updated |
| **Remaining Limitations** | `stage_scope_check` still calls `record_lineage` before checking — local disk write only, no network egress |
| **Current Status** | ✅ **EXISTS** |

---

## LEDGER-004 — Close `PolicyGate` Terminal-Command Bypass

| Field | Value |
|---|---|
| **Capability** | Enforce hard invariants (loopback / cloud metadata / reserved ranges) across **all** execution categories |
| **Previous Status** | ❌ Verified bypass: `curl http://169.254.169.254/latest/meta-data/` ⇒ **allowed** |
| **Files Inspected** | `core/control_plane/policy_gate.py:101-177` · `core/control_plane/computer_control.py:121,220` · `core/scope_engine.py:229-258` |
| **Files Changed** | `core/control_plane/policy_gate.py` · `core/scope_engine.py` · **new:** `tests/test_policy_invariants_on_commands.py` |
| **Change Description** | Root cause: `is_local_exec` treated any terminal command with `target=local_terminal` as local execution and skipped **all** scope checks — including the metadata check inside that branch. Fix: added a pre-exception step running on every category that extracts destinations from `url`/`target`/`command` via `extract_candidate_destinations()` (URLs + IPv4 + known metadata hostnames, **never matching file paths** or version numbers) and validates them via `check_inviolable()`. |
| **Tests Executed** | `pytest tests/test_policy_invariants_on_commands.py` (19 new tests) |
| **Test Results** | ✅ **19/19 passed**: metadata via terminal ⇒ denied · `metadata.google.internal` ⇒ denied · `127.0.0.1:8085` ⇒ denied · `localhost` ⇒ denied · `240.0.0.1` ⇒ denied · `rm -rf /` ⇒ denied (preserved) · `ls -la /tmp && cat /etc/hostname` ⇒ **allowed** (no over-blocking) · in-scope HTTP ⇒ allowed · out-of-scope HTTP ⇒ denied |
| **Remaining Limitations** | Tools executed directly via `ToolManager` (pipeline path) **bypass `PolicyGate` entirely** — audit gap S1, not addressed in this entry |
| **Current Status** | ✅ **EXISTS** (for paths traversing the gate) · ⚠️ Separate gap S1 remained `MISSING` until LEDGER-008 |

---

## LEDGER-005 — Record Tool Failures as Coverage Gaps

| Field | Value |
|---|---|
| **Capability** | Track, classify, and report tool failures instead of swallowing them |
| **Previous Status** | ❌ `MISSING` — `except Exception: logger.debug` in 15 sites + missing binaries indistinguishable from empty success |
| **Files Inspected** | `tools/tool_manager.py:8-25,194-259` · `hunter_ai/pipeline/tool_specs.py:712-790` · `hunter_ai/pipeline/pipeline_orchestrator.py` (call sites) |
| **Files Changed** | `tools/tool_manager.py` · `hunter_ai/pipeline/tool_specs.py` · `hunter_ai/pipeline/pipeline_orchestrator.py` · **new:** `tests/test_tool_failure_classification.py` |
| **Change Description** | **(1)** Added `error_category` to `ToolResult` and `classify_tool_failure()`: `except FileNotFoundError` can **never trigger** under `create_subprocess_shell`; missing binaries return exit 127/9009 with `error=None`. Failures are now classified as `TOOL_UNAVAILABLE` / `NONZERO_EXIT` / `TIMEOUT` / `EXECUTION_ERROR` using a strict shell-error regex (`sh: 1: foo: not found`) that avoids false positives on normal "record not found" output. **(2)** Added `fallback_empty` status when fallback yields zero items — no longer marked as success. **(3)** Single hook: `MasterToolRegistry.set_result_observer()` fires after every run, allowing the Orchestrator to log blindspots into `CoverageLedger` without editing 20 call sites. **(4)** Added `coverage_summary` and `tool_failures` to pipeline output and persisted `coverage_ledger.json`. |
| **Tests Executed** | `pytest tests/test_tool_failure_classification.py tests/test_tool_output_logging.py` · `python main.py -t https://example.com --mode recon --dry-run --allow-no-ai` · inspected `13_evidence/coverage_ledger.json` |
| **Test Results** | ✅ **13/13 passed**. ✅ E2E: **7 blindspots** logged that were previously swallowed (`subfinder`, `waybackurls`, `hakrawler`, `gau`, `ffuf`, `feroxbuster`, `gobuster`) · persisted file: `blindspots_count=7`, `assets_untestable=2` |
| **Remaining Limitations** | Classification relies on text patterns for some Windows cases; `ToolSpec.parser` remains text filtering rather than structural parsing; observer callback is synchronous |
| **Current Status** | ✅ **EXISTS** |

---

## LEDGER-006 — Unified Reasoning Engine (DeepSeek-R1 + Claude) Wired to Orchestrator

| Field | Value |
|---|---|
| **Capability** | Unified reflective reasoning layer feeding orchestrator decisions and logged to audit trail |
| **Previous Status** | `DISCONNECTED` — `ClaudeThinkingEngine` existed with no tests and no wiring; DeepSeek-R1 pattern did not exist |
| **Files Inspected** | `core/cognitive/claude_thinking_protocol.py` · `hunter_ai/brain/orchestrator_workers.py:407-450` · `hunter_ai/brain/cognitive_council.py` · `hunter_ai/runtime/meta_reasoning.py` · `agents/security_intelligence/brain.py` |
| **Files Changed** | `core/cognitive/__init__.py` · `hunter_ai/brain/orchestrator_workers.py` · **new:** `core/cognitive/deepseek_thinking_protocol.py` · `core/cognitive/hybrid_reasoning_core.py` · `tests/test_hybrid_reasoning.py` · `tests/test_orchestrator_workers.py` |
| **Change Description** | **(1)** `DeepSeekThinkingEngine`: problem decomposition, multi-path exploration (self-consistency), independent verification, **backtracking** on "wait" (aha) moments, rumination-halt overthinking control (per "Thoughtology" findings), agreement-calibrated confidence, and meta-review. **(2)** `HybridReasoningCore`: routes between Claude mode (8-stage structured/interleaved) and DeepSeek mode (reflective) by task complexity — matching Claude Adaptive Thinking. **(3)** Live wiring: `MasterOrchestratorEngine.decide_next_action()` injects the reasoning protocol into the system prompt and records the strategy in `BlackboardState.record_action`. Fail-safe: if the cognitive layer is unavailable, the orchestrator preserves its prior behavior. Private chain-of-thought is never exposed — only a concise decision summary (strategy/confidence/stats). **(4)** Decision-level self-consistency: when `reasoning_samples > 1`, the orchestrator runs multiple samples at higher temperature (0.7), picks the **majority-vote** action via `Counter`, and records `decision_agreement`. Default `1` ⇒ unchanged behavior and cost. |
| **Tests Executed** | `pytest tests/test_hybrid_reasoning.py tests/test_orchestrator_workers.py -v -p no:cacheprovider` · import check `python -c "import core.cognitive, hunter_ai.brain"` |
| **Test Results** | ✅ **31/31 passed** (22 reasoning engine + 9 orchestrator, including 6 new: 3 wiring + 3 majority voting). Testing surfaced and fixed **2 real logic bugs**: flattening order of VERIFY/BACKTRACK steps in `think()`, and the complexity evaluator misclassifying short analytical tasks as simple. |
| **Remaining Limitations** | Decision-level self-consistency is implemented and tested but **opt-in** (`reasoning_samples>1`) since it multiplies model calls; DeepSeek's `reasoner` callback remains an optional extension point not wired to a model on the decision path. |
| **Current Status** | ✅ **EXISTS** (engines + routing + audit + decision-level self-consistency) |

---

## LEDGER-007 — Derived (Not Declared) Proof Across Detectors and Vulnerability Pipeline

| Field | Value |
|---|---|
| **Capability** | Enforce a "re-evaluable proof" contract on every path submitting evidence to the court, removing declared-proof shortcuts that broke valid findings |
| **Previous Status** | `DISCONNECTED` — the court tightened to reject declared proofs, but detectors, vuln engine, and Burp validators still sent declared flags without proof payloads ⇒ 5 failing tests (`None`/zero findings) |
| **Files Inspected** | `core/evidence_court.py` · `core/poe_engine.py` · `core/detectors/xss_detector.py` · `core/detectors/sqli_detector.py` · `core/vuln_engine.py` · `hunter_ai/pipeline/pipeline_orchestrator.py` · `validate_burp_integration.py` · `validate_burp_e2e_v2.py` |
| **Files Changed** | Same files — added `ProofPayload.from_vuln_evidence`, wired `proof_payload` in detectors/engine/validators, and expanded `verify_sqli_extraction` |
| **Change Description** | **(1)** `ProofPayload.from_vuln_evidence(vuln_type, evidence)` — single builder for re-evaluable proof payloads (returns `None` when no PoE signature is present; never fabricates proof). **(2)** `pipeline_orchestrator._build_proof_payload` now delegates to it (removing duplication). **(3)** XSS detector passes token (nonce) proof with mutated and baseline responses. **(4)** SQLi detector passes differential proof (mutated vs. baseline). **(5)** `vuln_engine.assess_target` constructs payloads from `extracted_data`. **(6)** `ProofOfExecutionEngine.verify_sqli_extraction` now recognizes **Oracle** and **MSSQL** banners (hardening, not weakening). **(7)** Burp validators (CHECK-09/11) pass real token payloads. |
| **Tests Executed** | `pytest tests/test_v1_architecture.py tests/test_vuln_engine.py tests/test_burp_e2e_v2.py tests/test_burp_live_validation.py tests/test_proof_provenance.py tests/test_burp_gateway.py` · `tests/integration/test_evidence_court.py` · `tests/v27/*` · pipeline consumers |
| **Test Results** | ✅ **61/61** (focused) + 24 (court/PoE/v27) + 23 (pipeline) + 15 (master/workflow). Zero failures. |
| **Remaining Limitations** | Detectors relying strictly on a **version banner** are accepted as direct SQLi proof; arithmetic/error cases use differential proof (an approved court path). |
| **Current Status** | ✅ **EXISTS** (derived proof enforced and consumed on all tested paths) |

---

## LEDGER-008 — Tool Execution Governance (`ToolManager` → `PolicyGate`) Closing Gap S1

| Field | Value |
|---|---|
| **Capability** | Every tool execution passes through `PolicyGate` (fail-closed) with audit logging |
| **Previous Status** | `MISSING` (S1): `ToolManager.execute()` ran shell commands via `create_subprocess_shell` with no gate, and `ToolManager` is instantiated in ~15 places |
| **Files Inspected** | `tools/tool_manager.py` · `core/control_plane/policy_gate.py` · `core/system/terminal_bridge.py` (reference pattern) · `hunter_ai/pipeline/pipeline_orchestrator.py:209` |
| **Files Changed** | `tools/tool_manager.py` · `hunter_ai/pipeline/pipeline_orchestrator.py` · **new:** `tests/test_tool_manager_governance.py` |
| **Change Description** | **(1)** `ToolManager.__init__(..., policy_gate=None, project_id="default")` + `attach_policy_gate()` + `_govern()`: builds `ActionRequest(TERMINAL_COMMAND)`, extracts destinations via `extract_candidate_destinations`, calls `PolicyGate.evaluate` — **fail-closed** on any error, returning `ToolResult(error_category="POLICY_DENIED"/"POLICY_ERROR")` without executing. **(2)** Governance runs inside `execute()` **before** cache lookup and execution. **(3)** `pipeline_orchestrator` attaches its official gate to `self.tm` upon construction ⇒ all `NetworkTools`/`WebTools`/`MasterToolRegistry` calls are governed. **(4)** `governance_audit` records: `project_id`, `tool_id`, `action`, `timestamp`, verdict, and reason. |
| **Tests Executed** | `pytest tests/test_tool_manager_governance.py` + `test_policy_invariants_on_commands.py` · `test_tool_failure_classification.py` · `test_tool_output_logging.py` · `test_governed_tool_gateway.py` · `test_policy_engine.py` · `test_risk_classifier.py` + pipeline |
| **Test Results** | ✅ 61/61 (governance/tools) + 25 (master/workflow/scope) + 64 (pipeline consumers + orchestrator + reasoning + `terminal_bridge`). Zero failures. |
| **Remaining Limitations** | Destination extraction catches `http(s)` URLs, IPv4 literals, and blocked hosts only; bare hostnames (e.g., `nmap evil.net`) are treated as local tokens — allowlist enforcement for bare hostnames remains in the planner/`terminal_bridge` layer. |
| **Current Status** | ✅ **EXISTS** (fail-closed + audit log on every main-path tool execution) |

---

## LEDGER-009 — Court Gate on Hypothesis Promotion (`InvestigationController` → `EvidenceCourt`)

| Field | Value |
|---|---|
| **Capability** | Every "confirmed" finding produced by the OODA loop passes through `EvidenceCourt.adjudicate` before recording |
| **Previous Status** | `MISSING` — `_promote_to_evidence_court` directly built `HunterFinding(status=CONFIRMED)` and appended it to `self.orc.findings` **without calling the court**, trusting only the skill's declared flag (`objective_met`/`verified`) ⇒ court bypass |
| **Files Inspected** | `hunter_ai/pipeline/investigation_controller.py:498-686` · `core/evidence_court.py:136-158,545-624` · `hunter_ai/pipeline/pipeline_orchestrator.py:1698-1710` · `tests/test_parameter_intelligence_and_canonicalizer.py:185-262` |
| **Files Changed** | `hunter_ai/pipeline/investigation_controller.py` · **new:** `tests/test_investigation_court_promotion.py` |
| **Change Description** | **(1)** Promotion now calls `EvidenceCourt.adjudicate(...)` with `is_in_scope=True` and `allow_declared_proof=True` (the skill is a trusted internal verifier); a finding is recorded only if the court returns `CONFIRMED && reportable`. **(2)** `_COURT_FLAG_BY_VULN` mapping: maps each vulnerability class to its appropriate declared flag (`dom_breakout_confirmed` for XSS, `token_bypass_confirmed` for IDOR/SSRF, `template_eval_confirmed` for SSTI, `arithmetic_proof_confirmed` for CmdInjection, `file_content_confirmed` for LFI, `boolean_branch_confirmed` for SQLi). **(3)** `_verified_proof_payload`: attaches a proof payload **only** if the PoE engine itself confirms it can derive proof from it (avoiding false rejections of valid results), otherwise falling back to the tagged declared-proof path. **(4)** `run()`: if the court does not confirm, marks status `inconclusive` and down-ranks or rejects the hypothesis rather than tagging `CONFIRMED`. **(5)** Findings now carry `court_verdict`/`court_proof_strength`/`court_epistemic_state` inside `false_positive_checks`. |
| **Tests Executed** | `pytest tests/test_investigation_court_promotion.py` (5 new) · `pytest tests/test_parameter_intelligence_and_canonicalizer.py` (14) · pipeline consumers |
| **Test Results** | ✅ **5/5** (tagged declared · derived · denial drops · full loop records only court-confirmed · rejects unverified declared claim) + **14/14** existing. Zero failures. |
| **Remaining Limitations** | Skills that do not emit an explicit `proof_payload` confirm via the tagged declared path (`CONFIRMED_ON_DECLARED_PROOF`) rather than derived proof — future improvement: have skills emit re-evaluable token/differential payloads. |
| **Current Status** | ✅ **EXISTS** (no finding without a court ruling) |

---

## LEDGER-010 — Remove Dead Court-Bypassing Promotion Path (`raw_probe_findings`)

| Field | Value |
|---|---|
| **Capability** | Remove a dead parallel path that constructed `HunterFinding(status=CONFIRMED)` bypassing the court |
| **Previous Status** | `MISSING` — `raw_probe_findings = []` in `pipeline_orchestrator` was **never populated**, making both consumer loops (WhiteRabbitNeo strategy + ~330-line VERIFY block) **unreachable**, leaving `verified_findings` empty and `self.findings.extend([])` a no-op |
| **Files Inspected** | `hunter_ai/pipeline/pipeline_orchestrator.py:1678,1870-1887,1912-2245` · `git show HEAD:...` (confirmed pre-existing code, not uncommitted edits) |
| **Files Changed** | `hunter_ai/pipeline/pipeline_orchestrator.py` |
| **Change Description** | Deleted **336 dead lines**: `raw_probe_findings` initialization, the WhiteRabbitNeo loop over raw hypotheses, and the duplicate VERIFY block that built hardcoded-score Findings bypassing the court. Retained the `VERIFY` state transition as a stage marker. Verification is now handled through `InvestigationController` (LEDGER-009) + `FindingQualificationGate`. Zero runtime behavior change (the code was never executed). |
| **Tests Executed** | `python -m py_compile` · `pytest tests/test_hunter_master_pipeline.py tests/test_hunter_workflow_pipeline.py tests/test_enterprise_casm.py tests/test_program_intelligence_and_triad.py tests/test_artifact_based_recon.py tests/test_burp_pipeline_fusion.py` · `grep raw_probe_findings` |
| **Test Results** | ✅ **55/55 passed** (+2 re-run after freeing port 8085: passed) · zero remaining references aside from a doc comment. |
| **Remaining Limitations** | Deleting dead code adds no new capability; the real enforcement landed in LEDGER-009. |
| **Current Status** | ✅ **EXISTS** (bypass path removed; no parallel path outside the court) |

---

## LEDGER-011 — Eliminate Silent `CONFIRMED` (Schema Defaults + `EvidenceOS` Verdict + Team Reviewer Honesty)

| Field | Value |
|---|---|
| **Capability** | Close every path that silently marks a finding confirmed/verified without proof |
| **Previous Status** | `MOCKED` — four locations: (a) `HunterFinding.status=CONFIRMED` and `tier=VERIFIED_FINDING` by default in schema; (b) `EvidenceOS.rule_verdict(decision="CONFIRMED")` by default without calling `verify_claim_lineage`; (c) tautology `x.lower() in x.lower()` in `DeterministicEvidenceValidator.evaluate_differential_response` making length diff sufficient; (d) `EvidenceCourtReviewer` approving even `UNVERIFIED` verdicts and fabricating `poe_token` |
| **Files Inspected** | `hunter_ai/pipeline/schemas.py:199-200` · `core/evidence_os/unified_model.py:242` · `core/evidence_graph.py:252-271` · `core/teams/verification_team.py:98-189` · `tests/test_v4_evidence_os.py` · `tests/test_burp_pipeline_fusion.py` · `grep HunterFinding(`/`rule_verdict`/`evaluate_differential_response` |
| **Files Changed** | `hunter_ai/pipeline/schemas.py` · `core/evidence_os/unified_model.py` · `core/evidence_graph.py` · `core/teams/verification_team.py` · `tests/test_evidence_integrity_defaults.py` (new) |
| **Change Description** | 1) `HunterFinding` defaults changed to `UNVERIFIED`/`NEEDS_REVIEW` (promotion is explicit via the gate only). 2) `rule_verdict` defaults to `UNVERIFIED` and rejects `CONFIRMED` with `ValueError` unless claim lineage (Observation→…→Claim) verifies. 3) Removed tautology; now requires the diff marker to actually appear in `tampered_body`, and length difference alone is rejected. 4) `EvidenceCourtReviewer` re-adjudicates via `EvidenceCourt` using real differential payloads (`probed_text`/`baseline_text`) with no fabricated token, approving only `CourtVerdict.CONFIRMED`. 5) `CausalVerificationAgent` stops fabricating responses (rejects when measurements are absent) and attaches raw bodies for re-evaluation. |
| **Tests Executed** | `tests/test_evidence_integrity_defaults.py` (12) · `tests/test_v4_evidence_os.py` (14) · `tests/test_evidence_graph_and_lab_mode.py` + evidence suite (55) · `tests/test_hunter_master_pipeline.py tests/test_hunter_workflow_pipeline.py` (15) |
| **Test Results** | ✅ **96/96** across the 4 targets · ✅ **1262/1262** full-suite baseline on prior state (13 min) · full suite on new state confirmed in phase report |
| **Remaining Limitations** | Scanner gate sites (`dalfox`/`nikto`/`secrets`) still pass `reproduced` only ⇒ rejected by the court (honest behavior: no finding without proof) — addressed next by converting scanner signals into testable hypotheses. |
| **Current Status** | ✅ **EXISTS** (no silent `CONFIRMED` path in schema/`EvidenceOS`/court/team reviewer) |

---

## LEDGER-012 — Quick Baseline Hardening: Governance and Tool Hygiene (M0)

| Field | Value |
|---|---|
| **Capability** | Eliminate small, high-impact defects: open-by-default config, hardcoded LAN host, missing type import |
| **Previous Status** | `MOCKED`/`PARTIAL` — (a) `config/settings.yaml` declared `unrestricted_scope: true` and `auto_approve_all: true` with no reader; (b) `192.168.1.3` hardcoded in 6 production locations despite claiming `127.0.0.1`; (c) `core/tool_registry.py:211,259` referenced unimported `Tuple` |
| **Files Inspected** | `config/settings.yaml:28-33` · 6 host locations · `core/tool_registry.py` · `core/terminal_bridge.py` · `nvidia_test.py` search · `grep 192.168.1.3` · `grep settings.yaml` |
| **Files Changed** | `config/settings.yaml` · `core/tool_registry.py` · `hunter_ai/brain/model_router.py` · `core/ai_bridge/agent_ai_cognitive_bridge.py` · `core/pipeline/vram_sequential_pipeline.py` · `core/resilience/autonomous_healing_engine.py` · `models/ollama_manager.py` · `platform/kali.json` · `test_connection.py` · `tests/test_config_and_host_hygiene.py` (new) |
| **Change Description** | 1) `settings.yaml` permissions set to fail-closed (`false`) with a comment noting there is no reader. 2) Unified Ollama host to `os.getenv("OLLAMA_HOST", "http://127.0.0.1:11434")` across all production sites and removed the LAN IP from `OllamaManager` discovery. 3) Imported `Tuple` in `tool_registry` (preventive fix; note: `from __future__ import annotations` prevented a runtime `NameError`, so the audit overstated its impact). |
| **Tests Executed** | `tests/test_config_and_host_hygiene.py` (3) · `test_ai_model_connectivity` + `test_agent_ai_cognitive_bridge` + `test_vram_sequential_pipeline` (25) · `test_full_computer_agent.py` (14) · `py_compile` + `import` |
| **Test Results** | ✅ **42/42** across all 3 targets + clean compile/import |
| **Remaining Limitations** | Both P2-43 audit items were invalid: `nvidia_test.py` **does not exist**, and `core/terminal_bridge.py` is **actively used** (`tests/test_e2e_phase17.py:37`, `capability_matrix.json:38`) ⇒ kept. `sync.sh` is a dev sync script (port 9999) outside production scope ⇒ kept. `tests/test_vram_sequential_pipeline.py` explicitly passes a test host argument (not a production default). |
| **Current Status** | ✅ **EXISTS** |

---

## LEDGER-013 — Prevent Direct Writes to `CONFIRMED` (M1a / C7)

| Field | Value |
|---|---|
| **Capability** | No production path may declare `CONFIRMED` from a caller flag, LLM vote, or unsafe default |
| **Previous Status** | `PARTIAL` — (a) `core/arbitration_engine.py:82` wrote `LifecycleStage.CONFIRMED` from `tool_output.get("verified")`, and was **dead code** (zero importers) duplicating the court; (b) `core/evidence_os/unified_model.py:118` defaulted `Verdict.decision` to `CONFIRMED`; (c) `core/confidence_checker.py:518` mapped model consensus ≥0.65 ⇒ `CONFIRMED` (advisory signal) |
| **Files Inspected** | `core/arbitration_engine.py` · `core/confidence_checker.py` · `core/evidence_os/unified_model.py` · `core/evidence_court.py` (`_ProofResolver`) · `orchestrator/router.py` · `core/contract/security_contract.py` · full `grep` for `CONFIRMED` |
| **Files Changed** | **Deleted** `core/arbitration_engine.py` · `core/evidence_os/unified_model.py` · `core/confidence_checker.py` · `tests/test_no_direct_confirmation.py` (new) |
| **Change Description** | 1) Deleted `arbitration_engine` (dead code + direct write duplicating the court ⇒ do not wire). 2) Changed `Verdict.decision` default to fail-closed `"INCONCLUSIVE"`. 3) Model consensus now emits advisory `"CORROBORATED"` with an architectural note in docs and reports; LLM votes never produce `CONFIRMED`. 4) Guard test forbids writing `LifecycleStage.CONFIRMED` outside lifecycle/contract modules and verifies that bare caller flags fail while derived proof confirms. |
| **Tests Executed** | `tests/test_no_direct_confirmation.py` (5) + `test_evidence_integrity_defaults` + `test_v4_evidence_os` + `test_investigation_court_promotion` + `test_v8_investigation_os` + `test_v2_deep_architecture` + `test_scope_and_false_positives` |
| **Test Results** | ✅ **76/76 passed** + clean `py_compile` |
| **Remaining Limitations** | `core/contract/security_contract.py:97` retains `CONFIRMED`, derived from requirement checks + reproduction threshold (not a bare caller flag) ⇒ intentionally preserved. Remaining M1 items (V1/V2 unification, reflection signals, PoE wiring) = M1b..M1d. |
| **Current Status** | ✅ **EXISTS** |

---

## LEDGER-014 — Unify Courts V1 and V2 (M1b / C2)

| Field | Value |
|---|---|
| **Capability** | Single authoritative evidence court; V2 is a presentation facade delegating verdicts to V1, so it can never confirm what V1 rejects |
| **Previous Status** | `PARTIAL` — `core/court/evidence_court_v2.py:adjudicate_case` accepted caller-supplied `proof_nonce_proven: bool`, derived by the caller from free text (`has_arith = "72" in proof_reason`) ⇒ a byte diff became "proof" |
| **Files Inspected** | `core/court/evidence_court_v2.py` · `core/evidence_court.py` (`_ProofResolver`/`adjudicate`) · `core/poe_engine.py` · `core/orchestration/investigation_kernel.py` · `core/brain/autonomous_brain.py:2262-2349` · `cli/hunter_cli.py:666` |
| **Files Changed** | `core/court/evidence_court_v2.py` · `core/orchestration/investigation_kernel.py` · `tests/test_v8_investigation_os.py` · `tests/test_court_unification.py` (new) |
| **Change Description** | 1) V2 now calls `EvidenceCourt.adjudicate` and derives its ruling from it; `proof_nonce_proven` is tagged `DECLARED`, never `DERIVED`. 2) Extended `TribunalRuling` with `proof_strength`/`epistemic_state`/`court_judgment_id` (full transparency). 3) Verifier confirms only when V1 confirms + reproduction threshold (≥2) is met. 4) Skeptic can always downgrade. 5) `investigation_kernel` (deterministic simulation where it acts as verifier) explicitly passes `allow_declared_proof=True` ⇒ tagged `CONFIRMED_ON_DECLARED_PROOF` (no silent bypass). |
| **Tests Executed** | `tests/test_court_unification.py` (4) + `test_v8_investigation_os` + `test_v8_brain_integration` + `test_v19_epistemic_security_os` + `test_evidence_integrity_defaults` + `test_no_direct_confirmation` + `test_investigation_court_promotion` + `test_proof_provenance` (98) + `test_v16_benchmark_and_dashboard`/`test_execution_fabric_and_orchestration`/`test_governed_orchestrator`/`test_v3_provenance_platform`/`test_evidence_graph_and_lab_mode`/`test_evidence_driven_system` (54) |
| **Test Results** | ✅ **98/98** + **54/54 passed** + clean `py_compile` |
| **Remaining Limitations** | **(Critical conflict resolved)** A parallel process created a `core/evidence_court/` package that shadowed `core/evidence_court.py` and broke all court imports ⇒ moved to `core/exploit_verification/` and updated `core/web_dashboard/dashboard.py`. `autonomous_brain` still passed free-text flags (`has_arith`/`is_reflection`) ⇒ cleaned up in M1c. |
| **Current Status** | ✅ **EXISTS** |

---

## LEDGER-015 — Remove Reflection / Free-Text / Default-True Confirmations (M1c / C3+C4+C5)

| Field | Value |
|---|---|
| **Capability** | No finding may be confirmed from payload reflection, free-text matching, or default-true sensor signals |
| **Previous Status** | `PARTIAL` — (C3) `autonomous_brain` derived "proof" from `has_arith = "72" in proof_reason`; (C5) reflection counted as execution in `smart_probe_engine` (and byte expansion confirmed SQLi) and `independent_verifier` (`<tagxyz>123` in body ⇒ PROVEN); (C4) `SensorSignals`/`ConfidenceFactors` had default-true or hardcoded values (`dom_executed=True`, `diff_confirmed=True`, `poe_token_verified=bool(evidence)`, `reproducibility=1.0`, `negative_test_result=1.0`, `tool_agreement=0.9`) |
| **Files Inspected** | `core/brain/autonomous_brain.py` · `core/smart_probe_engine.py` · `core/independent_verifier.py` · `core/scoring/tool_agreement.py` · `core/scoring/confidence_calculator.py` · `core/poe_engine.py` · `core/causal/causal_graph.py` |
| **Files Changed** | `core/brain/autonomous_brain.py` · `core/smart_probe_engine.py` · `core/independent_verifier.py` · `tests/test_no_reflection_confirmation.py` (new) · `tests/test_evidence_court_single_authority.py` (new) |
| **Change Description** | (C3) Builds `ProofPayload.from_vuln_evidence(vt, probe_snippet)` from raw responses and sends it to the court; removed free-text matching (`has_arith`/`is_reflection`) and set `proof_nonce_proven=False`. (C5) `smart_probe_engine`: renamed `has_xss_exec` → `has_payload_reflection`, reflection no longer confirms, and byte growth is no longer proof. `independent_verifier`: XSS reflection ⇒ `is_proven=False` (reflection ≠ execution). (C4) `SensorSignals` and `ConfidenceFactors` switched to fail-closed, with `poe_token_verified` read from a real flag. **(Critical)** Re-fixed `core/evidence_court/` shadowing → `core/adversarial_court/` and added a permanent guard test. |
| **Tests Executed** | `test_no_reflection_confirmation.py` (4) + `test_evidence_court_single_authority.py` (2) + court/brain/evidence/`scope_and_false_positives`/`v2_deep_architecture`/`v19` suites (171) + `tests/v27` + `tests/integration` + orchestration/dashboard/Burp (107) |
| **Test Results** | ✅ **171/171** + **107/107 passed** + clean `py_compile` |
| **Remaining Limitations** | `causal_graph.build_standard_injection_chain` always returned `is_causally_proven=True` (static template without verification) — addressed in M1d. A parallel agent may recreate `core/evidence_court/` (the guard test catches it immediately). |
| **Current Status** | ✅ **EXISTS** |

---

## LEDGER-016 — Wire PoE and Convert Scanner Signals (M1d / Acceptance: `findings_count`)

| Field | Value |
|---|---|
| **Capability** | Every confirmed finding must rest on a re-evaluable PoE payload; non-re-evaluable scanner output becomes a **hypothesis**, not a confirmation, eliminating false "reproduced" claims |
| **Previous Status** | `PARTIAL` — 6 pipeline call sites automatically passed `verifier_result={"reproduced": True, "is_reflection": False}` with no proof (`subzy`/`nuclei`/`dalfox`/`nikto`/`SpecialFileHunter`/`SecretHunter`), satisfying the court's "independent verification" check with an unearned flag. Also, `causal_graph.build_standard_injection_chain` always returned `is_causally_proven=True` (static template adding `DATA_SINK → OBSERVABLE_RESPONSE` unconditionally). |
| **Files Inspected** | `hunter_ai/pipeline/pipeline_orchestrator.py` · `hunter_ai/pipeline/qualification_gate.py` · `core/evidence_court.py` (`adjudicate`/`_ProofResolver`) · `core/poe_engine.py` · `core/causal/causal_graph.py` · `core/brain/autonomous_brain.py` · `core/orchestration/investigation_kernel.py` |
| **Files Changed** | `hunter_ai/pipeline/pipeline_orchestrator.py` · `core/causal/causal_graph.py` · `core/brain/autonomous_brain.py` · `core/orchestration/investigation_kernel.py` · `tests/test_v8_brain_integration.py` · `tests/test_poe_pipeline_gate.py` (new) |
| **Change Description** | 1) `_court_verifier_result(payload, directly_observed=…)`: claims `reproduced` only when a directly observed, **re-evaluable** PoE payload exists (`bool(directly_observed and proof_payload)`); a scanner output line is not reproduction. 2) Replaced all 6 call sites: line-only scanners (`subzy`/`nuclei`/`dalfox`/`nikto`) no longer claim reproduction; `SpecialFileHunter`/`SecretHunter` (self-fetched assets) pass `directly_observed=True` with longer response text (`r.text[:4000]`) for LFI signature checks. 3) `_defer_hypothesis(...)`: every court-rejected candidate is saved as a hypothesis feeding investigation (`deferred_hypotheses.json`) instead of being dropped or confirmed. 4) `causal_graph.build_standard_injection_chain(..., observed_differential=False)`: causal impact edge (and proof) now requires an actual observation — breaking the tautology. |
| **Tests Executed** | `tests/test_poe_pipeline_gate.py` (5, new) + `test_v8_brain_integration` (4) + `test_v8_investigation_os`+`test_court_unification`+`test_no_reflection_confirmation`+`test_evidence_court_single_authority`+`test_no_direct_confirmation`+`test_proof_provenance`+`test_evidence_driven_system`+`test_scope_and_false_positives` (86) + `test_autonomous_brain_mission`+`test_autonomous_brain_state`+`test_agent_copilot_and_ui`+`test_autonomous_skills_arsenal`+`test_attack_graph_integration`+`test_meta_reasoning`+`test_integration_pipeline` (33) + pipeline (`test_hunter_master_pipeline`/`test_hunter_workflow_pipeline`/`test_enterprise_casm`/`test_program_intelligence_and_triad`/`test_artifact_based_recon`/`test_burp_pipeline_fusion`) (38) |
| **Test Results** | ✅ **9/9** + **86/86** + **33/33** + **38/38 passed** (166 total) + clean `py_compile` |
| **Remaining Limitations** | Classes without a PoE signature (`.env`/secrets/`SubdomainTakeover`/`NucleiExposure`/`XSS`/`MisconfigExposure`) cannot confirm by design (the court requires deterministic proof) ⇒ deferred as hypotheses. Expanding proof families = M5. Parallel agent may recreate `core/evidence_court/` (caught by guard test). |
| **Current Status** | ✅ **EXISTS** |

---

## LEDGER-017 — Unify Scope and Policy Engines (M2 / P1-35)

| Field | Value |
|---|---|
| **Capability** | Single reference scope engine (`StrictScopeEngine`) with all other guards delegating to it; no "open-by-default" policy engine |
| **Previous Status** | `PARTIAL` — `core/gateway/policy_engine.PolicyEngine` defaulted to `full_permissions=True` (`ScopeRule(target="*", mode=ACTIVE)` + repeat limit 99999) ⇒ open gate. `agents/security_intelligence/scope_guard.ScopeGuard` defaulted to `ScopeRule(target="*")`. `core/scope_guard.ScopeGuard` had zero IP invariants (permissive when allowlist is empty, with `in_scope=[]` in Burp). |
| **Files Inspected** | `core/gateway/policy_engine.py` · `core/scope_engine.py` · `core/scope_guard.py` · `core/network_scope_guard.py` · `agents/security_intelligence/scope_guard.py` · `agents/skills/safe_sqli_assessment.py` · `core/control_plane/policy_gate.py` · `core/governance/policy_engine.py` |
| **Files Changed** | `core/gateway/policy_engine.py` · `core/scope_guard.py` · `core/network_scope_guard.py` · `agents/security_intelligence/scope_guard.py` · `tests/test_scope_policy_unification.py` (new) |
| **Change Description** | 1) `PolicyEngine(full_permissions=False)` by default; when `scope_guard` is omitted, attaches `_ReferenceScopeGuard` delegating all checks to fail-closed `StrictScopeEngine`. 2) `enable_full_permissions()` is now explicit, logged opt-in (not default). 3) `agents...ScopeGuard` defaults to fail-closed (`target=""`). 4) `core/scope_guard.ScopeGuard` delegates hard invariants to the reference engine (preserving explicit lab IP overrides). 5) `NetworkScopeGuard` defaults to fail-closed. |
| **Tests Executed** | `tests/test_scope_policy_unification.py` (24) + `test_policy_engine`/`test_governed_tool_gateway`/`test_scope_and_false_positives`/`test_policy_invariants_on_commands` (38) + scope/governance/Burp suites (96) + network/v27/integration (82) + pipeline/governance (62) |
| **Test Results** | ✅ **24** + **38** + **96** + **82** + **62 passed** + clean `py_compile` |
| **Remaining Limitations** | `agents/skills/safe_sqli_assessment.py` still holds skill-local `ScopePolicy`/`ScopeGate` (4th implementation) — not yet unified. `core/gateway/policy_engine.py` and `core/governance/policy_engine.py` share the class name `PolicyEngine` (both now fail-closed) — renaming would break public imports. |
| **Current Status** | ✅ **EXISTS** |

---

## LEDGER-018 — Close IP Encoding Bypasses (M2 / P1-36)

| Field | Value |
|---|---|
| **Capability** | Every literal encoding of a blocked IP (loopback/metadata/RFC1918) is rejected — no alternate-encoding bypass |
| **Previous Status** | `PARTIAL` — `_check_hard_invariants` only called `ipaddress.ip_address`; encodings like `127.1`, `2130706433`, `0x7f000001`, `0177.0.0.1`, `::ffff:127.0.0.1`, and `[::1]` failed parsing, fell through as hostnames, and bypassed blocking (especially under permissive fallback). |
| **Files Inspected** | `core/scope_engine.py` (`_check_hard_invariants`, `is_allowed`, `_compile_rule`) |
| **Files Changed** | `core/scope_engine.py` |
| **Change Description** | Added `normalize_ip_literal()` handling standard dotted-quad, short dotted, decimal, hex, and octal forms (via `socket.inet_aton`) plus bracketed/zone-scoped/wrapped IPv6, resolving `::ffff:x` via `ipv4_mapped`. Wired into hard invariants. Fixed host parsing in `is_allowed` to support bracketed IPv6 with port. Added `ScopePolicy.fail_closed` (default `False` for backward compatibility). |
| **Tests Executed** | `tests/test_scope_policy_unification.py::test_reference_engine_blocks_forbidden_destination_encodings` (16 forms) + full scope suite (96) |
| **Test Results** | ✅ Passed (192 across M2 suites) + clean `py_compile` |
| **Remaining Limitations** | DNS rebinding (public hostname resolving to an internal IP) is out of scope — invariants operate on literals, not DNS resolution results. |
| **Current Status** | ✅ **EXISTS** |

---

## LEDGER-019 — Sanitize Secrets at Artifact Outputs (M2 / P0-15)

| Field | Value |
|---|---|
| **Capability** | No plaintext secret appears in any output artifact (`raw`/`parsed`/`meta`/`timeline`/`manifest`/`lineage`/`log`/reports) |
| **Previous Status** | `PARTIAL` — `save_tool_artifact` wrote `raw_output`/`parsed_data`/`command`/`error` verbatim; `save_stage_file`/`log`/`record_timeline_event`/`_save_manifest`/`_save_timeline`/`_save_lineage` skipped sanitization; `_generate_reports` wrote directly. |
| **Files Inspected** | `hunter_ai/pipeline/engagement_manager.py` · `hunter_ai/pipeline/pipeline_orchestrator.py` (`_save_stage_artifact`, `_generate_reports`) · `core/secret_sanitizer.py` |
| **Files Changed** | `hunter_ai/pipeline/engagement_manager.py` · `hunter_ai/pipeline/pipeline_orchestrator.py` · `core/secret_sanitizer.py` · `tests/test_artifact_secret_sanitization.py` (new) |
| **Change Description** | 1) `EngagementManager` holds a `SecretSanitizer` and redacts every output: `save_tool_artifact` (raw/command/parsed/error), `save_stage_file`, `log`, `record_timeline_event` (message+kwargs), `record_lineage` (`asset_value`/`metadata`), and `_save_manifest`/`_save_timeline`/`_save_lineage`. 2) `_generate_reports` sanitizes `findings_data` and both MD/HTML reports prior to writing. 3) Generalized connection-string matching in `SecretSanitizer` to cover any `scheme://user:pass@host` URI (previously postgres/mysql/redis only). |
| **Tests Executed** | `tests/test_artifact_secret_sanitization.py` (2) + `test_enterprise_casm`/`test_artifact_based_recon`/`test_program_intelligence_and_triad` (21) + pipeline (62) |
| **Test Results** | ✅ **2** + **21** + **62 passed** + clean `py_compile` |
| **Remaining Limitations** | Secret patterns cover major providers only; unknown high-entropy tokens are not automatically masked (candidate for expansion). |
| **Current Status** | ✅ **EXISTS** |

---

## LEDGER-019b — Owner Mode: Unrestricted Execution Permissions (M2.5 / Owner Request)

| Field | Value |
|---|---|
| **Capability** | Agent executes with **full permissions** by default: any target (including loopback/metadata/RFC1918), any command (no "destructive" block), no human approval gate, and no abort when the model server is unreachable. **Evidence integrity controls remain untouched** (PoE + secret redaction). |
| **Previous Status** | `PARTIAL` — all gates defaulted to fail-closed (LEDGER-017/018), destructive commands blocked (`PolicyGate`), human approval required, and local Ollama triad mandatory (aborts when offline). |
| **Files Inspected** | `core/scope_engine.py` · `core/gateway/policy_engine.py` · `core/control_plane/policy_gate.py` · `core/execution_modes.py` · `core/governance/task_router.py` · `core/governance/policy_engine.py` · `core/scope_guard.py` · `core/network_scope_guard.py` · `agents/security_intelligence/scope_guard.py` · `agents/skills/safe_sqli_assessment.py` · `hunter_ai/pipeline/pipeline_orchestrator.py` · `main.py` |
| **Files Changed** | `core/security_mode.py` (new) · `core/scope_engine.py` · `core/gateway/policy_engine.py` · `core/control_plane/policy_gate.py` · `core/execution_modes.py` · `core/governance/task_router.py` · `core/governance/policy_engine.py` · `core/scope_guard.py` · `agents/security_intelligence/scope_guard.py` · `agents/skills/safe_sqli_assessment.py` · `hunter_ai/pipeline/pipeline_orchestrator.py` · `main.py` · `tests/conftest.py` (new) · `tests/test_unrestricted_mode.py` (new) |
| **Change Description** | Single toggle `core/security_mode.unrestricted_mode()` reads `HUNTER_UNRESTRICTED` and defaults to **enabled** (full permissions). Wired into: `StrictScopeEngine.is_allowed`/`_check_hard_invariants`, `PolicyEngine` (all requests allowed; TIER-4 not blocked), `PolicyGate.evaluate`, `HumanApprovalGate`, `ModeManager.assert_active_allowed`, `GovernedTaskRouter`/`GovernancePolicyEngine.requires_human_approval`, `core.scope_guard.ScopeGuard`, `agents...ScopeGuard`, SQLi skill `ScopeGate`, and `HunterPipelineOrchestrator.__init__` (forces `authorized=True`, `no_destructive_tests=False`, `allow_no_ai=True`). Inverse toggle: `HUNTER_UNRESTRICTED=0` or `python main.py --governed`. `tests/conftest.py` enforces governed mode during tests, while `tests/test_unrestricted_mode.py` verifies unrestricted execution **and proves that unverified findings are still rejected** (PoE) and secret sanitization still runs. |
| **Tests Executed** | `tests/test_unrestricted_mode.py` (12, new) + security/governance/scope suites (91) + pipeline/v27/integration (151, excluding 4 Ollama-dependent tests) |
| **Test Results** | ✅ **12** + **91** + **151 passed** + clean `py_compile` |
| **Remaining Limitations** | 4 pipeline tests (`test_orchestrator_safe_mode_restricted`/`test_orchestrator_authorized_mode`/`test_orchestrator_passive_profile_and_diff`/`test_orchestrator_artifact_generation`) require a running Ollama server (environmental — verified failing on HEAD via `git stash`). |
| **Current Status** | ✅ **EXISTS** |

---

## LEDGER-020 — Unified Model Router (M3a / Cloud-First ↔ Local)

| Field | Value |
|---|---|
| **Capability** | Single catalog for all models (local + all cloud providers) and unified policy: **cloud-first if a key is configured, otherwise local**; nothing hardcoded to a single provider |
| **Previous Status** | `PARTIAL` — `models/api/*` (gemini/openai/anthropic/deepseek/groq/openrouter/taskade) existed but were unwired from any unified router; general chat (`orchestrator/router._general_route`) was hardcoded to local Ollama (`qwen2.5-coder:14b`); pipeline required the Ollama triad. |
| **Files Inspected** | `models/api/*_provider.py` · `models/base_model.py` · `models/ollama_manager.py` · `core/llm_config/manager.py` · `config/models.yaml` · `core/smart_orchestrator.py` · `orchestrator/router.py` · `ui/web/app.py` |
| **Files Changed** | `core/llm_router.py` (new) · `orchestrator/router.py` · `ui/web/app.py` · `tests/test_llm_router.py` (new) |
| **Change Description** | `LLMRouter` aggregates cloud providers (ordered by owner priority: Gemini → DeepSeek → Claude → OpenAI → Groq → OpenRouter → Taskade) + Ollama models into one catalog and provides a unified `complete()` obeying `HUNTER_LLM_POLICY` (`cloud_first` default, plus `local_first`/`local_only`/`cloud_only`). ID format: `api:<provider>:<model>` and `local:<model>`. Added `GET /api/models/catalog` for the UI and wired `_general_route` to the router (cloud-first with safe local fallback). |
| **Tests Executed** | `tests/test_llm_router.py` (14, new) + `test_ai_model_connectivity`/`test_agent_copilot_and_ui`/`test_ai_diagnostics`/`test_static_reasoning_engine` (30) |
| **Test Results** | ✅ **14** + **30 passed** + clean `py_compile` |
| **Remaining Limitations** | Claude-style chat UI (model picker + streaming) = next step (M3b). Pipeline triad (`AIPreflightGate`) was not yet connected to the cloud router — still probed local Ollama only. |
| **Current Status** | ✅ **EXISTS** |

---

## LEDGER-021 — Claude-Style Chat UI (M3b)

| Field | Value |
|---|---|
| **Capability** | Clean chat-first interface at `/chat`: conversation sidebar + unified model picker (all providers) + live "execution steps" panel + Markdown renderer |
| **Previous Status** | `PARTIAL` — existing UI (`index.html`) was a general dashboard; chat was a small pane with no unified model picker, and legacy `api:<model>` always routed through OpenRouter. |
| **Files Inspected** | `ui/web/app.py` (`/`, `/ws/chat`) · `ui/web/templates/index.html` · `ui/web/static/app.js` · `core/smart_orchestrator.py` (`chat`) |
| **Files Changed** | `ui/web/templates/chat.html` (new) · `ui/web/static/chat.css` (new) · `ui/web/static/chat.js` (new) · `ui/web/app.py` (`/chat` route) · `core/smart_orchestrator.py` (routing `api:<provider>:<model>` via router) · `tests/test_chat_ui.py` (new) |
| **Change Description** | `/chat` serves `chat.html`, with `chat.css`/`chat.js` under `/static`. UI features: sidebar (New chat + `localStorage`-persisted conversation list + model picker populated from `GET /api/models/catalog` grouped by provider, defaulting to **first cloud model** per owner policy), assistant/user message bubbles, and an "execution steps" log driven by real WebSocket events (`chat_start`/`task_classified`/`step`/`step_done`/`route_done`) — no fake streaming. Safe Markdown-lite renderer (HTML-escaped first). Supports `Shift+Enter`, copy response, delete conversation, and automatic dark mode. Wired `SmartOrchestrator.chat` to the router for `api:<provider>:<model>` while retaining legacy `api:<model>` (via OpenRouter) for backward compatibility. |
| **Tests Executed** | `tests/test_chat_ui.py` (4, new) + `test_agent_copilot_and_ui`/`test_ai_model_connectivity`/`test_ai_diagnostics`/`test_llm_router`/`test_unrestricted_mode` (39) + live `TestClient` check (`/chat`=200, assets=200, `cloud_first` catalog with 3 options) |
| **Test Results** | ✅ **4** + **39 passed** + clean `py_compile` |
| **Remaining Limitations** | No real token streaming yet (cloud providers returned full text; local `chat_stream` unwired) — **closed in LEDGER-022**. Pipeline cloud triad (`AIPreflightGate`) unwired — **closed in LEDGER-023**. |
| **Current Status** | ✅ **EXISTS** |

---

## LEDGER-022 — Real Token Streaming Through the Router

| Field | Value |
|---|---|
| **Capability** | Real token streaming from model to UI: every cloud adapter + local Ollama streams via `on_token`, and the UI renders output incrementally |
| **Previous Status** | `MISSING` — `SmartOrchestrator.chat` called `complete()` and returned full text; UI showed loading dots then dumped the entire reply |
| **Files Inspected** | `models/ollama_manager.py` (`chat_stream` existed unused) · `models/api/*_provider.py` · `models/base_model.py` (`ModelResponse`) · `core/llm_router.py` · `core/smart_orchestrator.py` · `ui/web/app.py` (`/ws/chat`) · `ui/web/static/chat.js` |
| **Files Changed** | `models/api/{gemini,openai,deepseek,groq,anthropic,openrouter}_provider.py` (added `stream()`) · `core/llm_router.py` (`complete_stream`, `_dispatch_stream`, `_stream_provider`, `_complete_{cloud,local}_stream`) · `core/smart_orchestrator.py` (`_emit_token` + `complete_stream` in `api:` branch) · `ui/web/static/chat.js` (`token` event handler) · `tests/test_llm_streaming.py` (new) |
| **Change Description** | Each provider uses its native transport: Gemini via native SSE (`streamGenerateContent?alt=sse`), Anthropic via SDK stream, OpenAI/DeepSeek/Groq via SDK `stream=True`, and OpenRouter via SSE over `httpx`. Router tries `stream()` first and, if unsupported (e.g., Taskade), emits the full response as a single chunk — **no simulated streaming**. Local models use existing `OllamaManager.chat_stream`. `SmartOrchestrator` emits `token` events over WebSocket, and `chat.js` appends them incrementally. |
| **Tests Executed** | `tests/test_llm_streaming.py` (9) + **live verification** against Gemini: `complete_stream` returned `STREAMED=True` across 2 real chunks with joined tokens == content |
| **Test Results** | ✅ **9** + 74 regression + 1 live (opt-in `HUNTER_LIVE_LLM=1`) |
| **Remaining Limitations** | Streaming for the `auto` branch (smart task router) — **closed in LEDGER-025**. Streaming applied to manually selected models (UI default). |
| **Current Status** | ✅ **EXISTS** |

---

## LEDGER-023 — Cloud-Aware Triad Preflight Gate (Pipeline ↔ Router)

| Field | Value |
|---|---|
| **Capability** | Do not abort the pipeline when local Ollama is down as long as a cloud key is configured — adopt the cloud cognitive layer via the unified router |
| **Previous Status** | `PARTIAL` — `AIPreflightGate` probed Ollama only; if offline, it aborted runs in governed mode (`ABORTED`) with no cloud fallback |
| **Files Inspected** | `hunter_ai/brain/ai_preflight.py` · `hunter_ai/pipeline/pipeline_orchestrator.py` (`stage_ai_preflight`) · `hunter_ai/pipeline/state_machine.py` (transition rules) · `core/llm_router.py` |
| **Files Changed** | `hunter_ai/brain/ai_preflight.py` (`backend`/`backend_detail` + `_cloud_ready` + `cloud_backend` in `run_preflight`/`run_preflight_async` + banner) · `hunter_ai/pipeline/pipeline_orchestrator.py` (`_resolve_cloud_backend`, `ai_backend`, cloud FSM path, `preflight_cloud` event) · `tests/test_cloud_preflight.py` (new) |
| **Change Description** | Pipeline passes `cloud_backend` (first enabled router provider) into the preflight gate. If local fails, the gate emits `AI_READY` with `backend="cloud"` while **keeping `online=False`** (honest reporting: the local host really is down). FSM transitions cleanly through `AI_CONNECTING → MODEL_VERIFYING → INFERENCE_VERIFYING → AI_READY` (a direct jump was disallowed — caught in live testing and fixed). Banner reports the active cloud provider. |
| **Tests Executed** | `tests/test_cloud_preflight.py` (9, including an integration test instantiating the real Orchestrator confirming `stage_ai_preflight()==True`, `ai_backend=="cloud"`, and `online=False`) + 23 in `test_ai_preflight` + **live integration test** with real key |
| **Test Results** | ✅ **9** + **23** + live check: `returns=True`, `ai_backend=cloud`, `AI_READY`, `online=False`, `preflight_cloud` |
| **Remaining Limitations** | `LocalTriadAgent` (in-stage cognitive analysis) remains local; cloud fallback is approved at preflight. Wiring cloud inference inside analysis stages is a follow-up task. |
| **Current Status** | ✅ **EXISTS** |

---

## LEDGER-024 — Fix Cloud Model Catalog (Dead Model IDs)

| Field | Value |
|---|---|
| **Capability** | Executable cloud model catalog (no 404 model IDs) |
| **Previous Status** | `BROKEN` — `CLOUD_PROVIDERS` (Gemini) listed `gemini-2.0-flash`/`2.5`/`1.5-pro`, all returning **HTTP 404 "no longer available"** against the live API (discovered during live testing) |
| **Files Inspected** | `core/llm_router.py` · `models/api/gemini_provider.py` |
| **Files Changed** | `core/llm_router.py` (Gemini models) · `models/api/gemini_provider.py` (default) · `tests/test_llm_router.py` (updated expectations) |
| **Change Description** | Updated Gemini IDs to verified working models (`gemini-3.8-flash`, `gemini-flash-latest`) after proving both via live calls and SSE streaming. |
| **Tests Executed** | Live probe of 12 model IDs (OK/404) + live `streamGenerateContent` call |
| **Test Results** | ✅ Two working, streaming model IDs confirmed |
| **Remaining Limitations** | Model IDs for other cloud providers were not live-tested (no keys available on this host). |
| **Current Status** | ✅ **EXISTS** |

---

## LEDGER-025 — `auto` Route Streaming + Classifier Keyword Matching Fix (Closes LEDGER-022 Limitation)

| Field | Value |
|---|---|
| **Capability** | Real token streaming under "Auto (smart router)" across **all** routes (cloud and local) with accurate task classification |
| **Previous Status** | `PARTIAL` — three gaps: (a) `orchestrator/router._general_route` called `LLMRouter.complete()` (non-streaming) ⇒ zero deltas; (b) local routes emitted `chat_token` events ignored by `chat.js`; (c) `TaskClassifier` matched keywords via `kw in text`, so the single-letter keyword `"r"` matched **inside** `user`/`vulnerability`/`through` — combined with injected English memory context, almost every prompt (even Arabic) was classified as `CODING`, never reaching the cloud `GENERAL` route |
| **Files Inspected** | `orchestrator/router.py` · `core/smart_orchestrator.py` · `orchestrator/task_classifier.py` · `orchestrator/resource_manager.py` (`run_local_model` streams via `chat_stream`) · `ui/web/static/chat.js` · `ui/web/static/app.js` (legacy `chat_token` consumer) · `ui/web/app.py` (`/ws/chat`) |
| **Files Changed** | `orchestrator/router.py` · `core/smart_orchestrator.py` · `orchestrator/task_classifier.py` · `ui/web/static/chat.js` · `tests/test_auto_route_streaming.py` (new) · `tests/test_task_classifier_routing.py` (new) |
| **Change Description** | 1) `ModelRouter.route(..., on_token=None)` and `_general_route` now use `complete_stream` ⇒ emits `token` deltas (same transport as `api:`). 2) `auto` branch in `SmartOrchestrator.chat` passes `on_token=self._emit_token`. 3) `chat.js` handles `chat_token` (local: `{token}`) identically to `token` (cloud: `{delta}`) — **event name unchanged** (backward compatible with `app.js`). 4) `_keyword_present()` in classifier: word-boundary matching for alphabetic/spaced terms and substring matching for symbol terms (`c++`/`c#`/`ci/cd`) and Arabic terms ⇒ eliminates false positives on `"r"`. |
| **Tests Executed** | `tests/test_auto_route_streaming.py` (4, new) + `tests/test_task_classifier_routing.py` (6, new) + `test_ai_model_connectivity`/`test_agent_copilot_and_ui`/`test_llm_streaming`/`test_chat_ui` (19) + **live 3-case verification** |
| **Test Results** | ✅ **10** new + **19** regression + live check: `CODING` → local Qwen (**142** `chat_token` events, joined == content) · `GENERAL` → cloud Gemini (**2** `token` deltas, joined == content) · Arabic → cloud `GENERAL` |
| **Remaining Limitations** | `_security_route` cloud fallback (`_call_security_api`) does not stream (invoked only when Ollama is down). Security queries on `auto` route to the **local** triad by `ModelRouter` design (local-first policy), whereas the unified router (cloud-first) serves `GENERAL` and `api:`. Aligning `auto` policy with the owner's cloud-first policy is a separate design decision. |
| **Current Status** | ✅ **EXISTS** |

---

> **Numbering note (approved 2026-10-17):** The owner-requested model/UI track (`LEDGER-020…025`) used the IDs originally reserved in the plan for `M3` (`020…022`) and `M4` (`023…026`). **Owner decision:** shift plan phases by +6 — `M3 → 026…028` · `M4 → 029…032` · `M5 → 033…035` · `M6 → 036…038`. Applied in `docs/IMPLEMENTATION_PLAN.md`.

---

## Intentionally Out of Scope for This Session

| Item | Status | Reason |
|---|---|---|
| Derived (not declared) proof in `EvidenceCourt` | ✅ `EXISTS` (LEDGER-007) | Enforced contract and wired re-evaluable payloads across detectors, vuln engine, and both Burp validators |
| Court-bypassing `_promote_to_evidence_court` path | ✅ `EXISTS` (LEDGER-009) | Every finding now passes through `EvidenceCourt.adjudicate` (tagged declared / derived) — no finding without a court ruling |
| Empty `raw_probe_findings` (340 lines of dead code) | ✅ `EXISTS` (LEDGER-010) | Removed dead court-bypassing path (336 lines); capability covered by LEDGER-009 |
| Gap S1: ungated `ToolManager` execution | ✅ `EXISTS` (LEDGER-008) | Wired `ToolManager.execute` to fail-closed `PolicyGate` + audit log; bare-hostname allowlist remains open |
| `core/teams` (18 mocked agents + dead code) | `PARTIAL` | Phase 2 — made `EvidenceCourtReviewer` honest and removed fabrication in `CausalVerificationAgent` (LEDGER-011); remaining teams are still mocked |
| Silent `CONFIRMED` defaults (schema + `EvidenceOS` + team reviewer) | ✅ `EXISTS` (LEDGER-011) | Removed unsafe defaults, rejected `CONFIRMED` without lineage, made reviewer honest |
| Independent review in `TaskScheduler` | `PARTIAL` | Phase 2 |
| Unified shared memory (6 stores) | `MISSING` | Phase 6 |
| "Air-gapped" claim with active Gemini key | `DISCONNECTED`/risk | Requires owner decision before changing |

---

## How to Reproduce Results

```powershell
cd E:\Agant\PentestAI-Unified

# 1) Collection health and baseline
python -m pytest tests --collect-only -q -p no:cacheprovider

# 2) Focused tests for the five changes
python -m pytest tests/test_policy_invariants_on_commands.py tests/test_tool_failure_classification.py `
                 tests/test_v18_auditable_security_platform.py tests/test_v2_deep_architecture.py -q

# 3) Pipeline path tests
python -m pytest tests/test_hunter_master_pipeline.py tests/test_hunter_workflow_pipeline.py `
                 tests/test_enterprise_casm.py tests/test_scope_and_false_positives.py -q

# 3b) Evidence integrity: prevent silent CONFIRMED (LEDGER-011)
python -m pytest tests/test_evidence_integrity_defaults.py tests/test_v4_evidence_os.py `
                 tests/test_evidence_graph_and_lab_mode.py -q

# 4) Previously broken CLI
python cli\hunter_cli.py coverage --domain example.com

# 5) Rejection before network egress
'{ "allowed_targets": ["example.com"] }' | Set-Content scratch\scope.json
python main.py -t https://evil.example.net --scope-file scratch\scope.json --dry-run --allow-no-ai

# 6) Coverage gaps
python main.py -t https://example.com --mode recon --dry-run --allow-no-ai
```
