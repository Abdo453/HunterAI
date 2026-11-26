# HunterAI — Actual Implementation Audit Report (Phase Zero)

> **Audit Date:** 2026-10-16
> **Scope:** `E:\Agant\PentestAI-Unified` — source code review and live execution only.
> **Governing Rule:** Every verdict in this report is backed by a specific file and line number or a live run. No verdict is based on documentation or README claims.
> **Verdict Codes:** `EXISTS` present and working · `PARTIAL` partially implemented · `MOCKED` mocked or hardcoded data · `MISSING` absent or dead code · `UNVERIFIED` insufficient evidence.

---

## 1. Executive Summary

**Verdict distribution across 95 audited components in 9 areas:**

| Verdict | Count | Meaning |
|---|---|---|
| `EXISTS` | 20 | Actually works |
| `PARTIAL` | 28 | Present but incomplete or disconnected |
| `MOCKED` | 24 | Mocked or hardcoded data presented as results |
| `MISSING` | 23 | Absent or dead code |
| `UNVERIFIED` | 0 | Nothing left without evidence |

The 9 areas: Entry Points · Agents · Tools · Local Models · Scope & Governance · Memory & Event Bus · Court & Graphs · Tests · Contracts.

This is **not** a vaporware project: there is a real implementation of an end-to-end recon pipeline, a subprocess-based tool runner, 14 testing skills making real `httpx` requests, a seriously written evidence court, a coverage ledger, and task contracts. The pipeline **actually runs end-to-end** on this machine and produces reports and Desktop exports.

However, **three governing findings** reorder the priority list:

### 🔴 Finding 1 — EvidenceCourt validates claim *shape*, not evidence *provenance*

`FindingQualificationGate.evaluate_candidate()` passes the caller-supplied `verifier_result` directly to `EvidenceCourt.adjudicate()`, and the court treats evidence as "deterministic" if any boolean flag supplied by the caller itself is set (`core/evidence_court.py:331-343`).

**Live experiment executed on this repository:**

| Case | Input | Result |
|---|---|---|
| a) Pipeline scanner path (`{"reproduced": True, "is_reflection": False}`) | Exact payload `pipeline_orchestrator.py` passes for nuclei/dalfox/nikto/subzy | ❌ `UNVERIFIED` — never accepted |
| b) Same claim + `canary_confirmed=True` | One extra boolean flag from the caller | ✅ `CONFIRMED` |
| c) **Completely fabricated claim**, `raw_evidence=""`, `source_tool="llm_hallucination"` + two boolean flags | No tool ran, no evidence exists | ✅ **`CONFIRMED`** with a "complete Evidence Chain" |

Result: the system is simultaneously **unable to confirm anything through its own pipeline** and **able to confirm anything** if a caller (including an LLM-driven component) sets the right flag. This contradicts the central claim in `ARCHITECTURE.md:86-91`.

### 🔴 Finding 2 — The main pipeline can never produce a confirmed finding

- Every call to `FindingQualificationGate.evaluate_candidate()` in the pipeline (6 call sites) passes only `verifier_result={"reproduced": True, "is_reflection": False}` with no deterministic proof flag → the court always returns `UNVERIFIED` → `is_q=False` → nothing is appended to `self.findings`.
- The entire "TRANSITION TO VERIFICATION" block (`pipeline_orchestrator.py:1787-2124`, ~340 lines) iterates over `raw_probe_findings`, which is initialized as an empty list at `pipeline_orchestrator.py:1558` and **never appended to anywhere in the file** → the entire block is dead code.

**Experimental confirmation:** Running `python main.py -t https://example.com --mode recon --dry-run --allow-no-ai` finished with `status: completed` and **`Confirmed Findings: 0`**, matching `.agent/mission.md`, which logs "Total verified findings: 0" on every mission.

### 🔴 Finding 3 — A second confirmation path bypasses the court completely

`InvestigationController._promote_to_evidence_court()` — despite its name — **never calls `EvidenceCourt`**; it directly constructs `HunterFinding(status=CONFIRMED, reproducible=True)` and appends it to `orc.findings` (`hunter_ai/pipeline/investigation_controller.py:632-668`), trusting the `confirmed` flag returned by the skill (`:733-739`).

Result: the court is not the sole confirmation gate; a parallel ungoverned path exists. Yet `qualification_gate.py:8-10` explicitly states that "every confirmed finding must hold a connected evidence chain adjudicated by the court."

---

## 2. Methodology

| Step | What Was Actually Run |
|---|---|
| Code review | 6 parallel auditors across 6 areas + direct audit of the critical path |
| Test execution | Full `pytest tests` suite (results in §3) |
| Certification | `python certify.py` |
| E2E run | `python main.py -t https://example.com --mode recon --dry-run --allow-no-ai` |
| Live session | `python run_unified_live_session.py` (in-process managed local target) |
| Targeted experiments | Qualification gate tested under 3 cases (table above) |
| Reference analysis | Checked which components under `core/` have zero callers anywhere |

---

## 3. Measured State (Observed, Not Reported)

| Metric | Actual Result | Note |
|---|---|---|
| `pytest tests` | **1052 passed / 12 failed** + **5 files failed to collect** (1064 collected) | Duration: 7m 52s |
| Collection failure cause | `ImportError: cannot import name 'CoverageStatus'` | See §5.1 |
| `python certify.py` | **15/15 passed in 7.18 seconds** | Gates are fast enough to indicate shallow structural checks |
| E2E pipeline | `status: completed` · 1 subdomain · 1 live host · **0 findings** | Runs and emits artifacts |
| `run_unified_live_session.py` | ✅ Passed: Metamorphic Triad → `CONFIRMED` → Burp export | Real harness working against a local target |
| `tests/test_agent_teams_benchmark.py` | **7/10** when run directly; **0 tests** collected by pytest | Not a pytest file |
| Side effects | Running tests and `certify.py` mutates git-tracked files | `PRE_KALI_CERTIFICATION.md` + 6 SQLite DBs + `data/memory/*.json` |

---

## 4. Component Verdict Tables

### 4.1 Entry Points and Interfaces

| Component | Path | Verdict | Evidence |
|---|---|---|---|
| `main.py` (web/CLI/scanner) | `main.py:26-191` | EXISTS | Three real working execution paths |
| `hunter_ai` pipeline | `main.py:116-158` | EXISTS | Executed live and finished `completed` |
| `cli/hunter_cli.py` (68 commands) | `cli/hunter_cli.py:50` | **MISSING (broken)** | Crashes on import: `CoverageStatus` missing → all 68 commands are dead |
| FastAPI web UI | `ui/web/app.py` (1908 lines, ~40 routes) | EXISTS | Real routes |
| TUI | `ui/tui/hunter_os.py` | EXISTS | Textual, 4 tabs |
| `certify.py` | `certify.py:90-771` | PARTIAL | 15 gates pass in 7s — structural checks rather than live execution |

### 4.2 Agents and Teams Layer

| Component | Path | Verdict | Evidence |
|---|---|---|---|
| Contracts `ToolExecutionResult`/`TaskContract` | `core/contracts/task_contracts.py:76-210` | EXISTS | Real dataclasses + enforced state machine |
| `core/teams/*` (18 agents) | `core/teams/recon_team.py:46-58` and siblings | **MOCKED** | Hardcoded data (`api./auth./admin.`, `93.184.216.34`, ports `[80,443,8443]`, `nginx/1.24.0`, `pk_live_****`); zero network or subprocess imports in the entire package |
| Team reviewers | `core/teams/recon_team.py:128-151` | PARTIAL | Auto-approve and write fabricated data into `CoverageLedger` |
| `core/teams` package | `core/teams/__init__.py:12` | **MISSING (dead code)** | Zero production callers; sole caller is `tests/test_agent_teams_benchmark.py:27` |
| `agents/` (legacy layer) | `agents/recon_agent.py:33` · `agents/web_agent.py:45-58` | EXISTS | Runs nmap/gobuster/nuclei/sqlmap/dalfox and parses real stdout |
| `agents/skills/*` (14 skills) | `agents/skills/ssrf_skill.py:44-63` · `idor_skill.py:178-219` | EXISTS | Real `httpx` requests and real response differential checks |
| `agents/autonomous_mission_agent.py` | `:312` | PARTIAL | `Path` used without import → `NameError` swallowed at `:362` → knowledge base ingestion is dead |
| `hunter_ai/agents/*_contract_agent.py` | `web_contract_agent.py:81-141` | **MOCKED** | Hardcoded response bodies + SQLi finding with 0.98 confidence regardless of target |
| `core/multi_agent/specialists.py` | `:47-317` | MOCKED | Hardcoded ports/tenants + fabricated 1420-byte delta |
| `core/swarm/swarm_coordinator.py` | `:105-206` | MOCKED | Hardcoded lists and fabricated `boundary_isolation_verified` |
| `core/subagent_manager_v2.py` | `:87-141` | MOCKED | `launch_subagent` only appends a dataclass in `RUNNING` state |
| `core/system/task_scheduler.py` | `:216-291` | PARTIAL | Real state machine, but self-review guard is broken (§5.4) |
| `core/blackboard/agent_blackboard.py` | `:42-80` | EXISTS (unwired) | Zero production callers |

### 4.3 Tools and Execution Layer

| Component | Path | Verdict | Evidence |
|---|---|---|---|
| `ToolManager` (sole real executor) | `tools/tool_manager.py:224` | EXISTS | `asyncio.create_subprocess_shell` with timeout and output persistence |
| `MasterToolRegistry.execute_artifact` | `hunter_ai/pipeline/tool_specs.py:712-790` | EXISTS | `await self.tm.execute(...)` at `:741` |
| Tool output parsers | `tool_specs.py:62,129,162,196,230,377,487,563` | PARTIAL | Substring filtering instead of structural parsing; `ffuf` spec requests JSON then reads line-by-line |
| `crtsh` adapter | `tool_specs.py:109` → `:730` → `:764-770` | **MOCKED** | `command_template=""` → runs the tool name as a command → exit 127 → still reports `status="success"` |
| `BurpRepeaterController` | `core/controllers/burp_controller.py:80-84` | **MOCKED** | `status = 200` and `body` fabricated locally, then saved to `burp_repeater_experiments.json` |
| `hunter_ai/tools/tool_router.py` | `:96-104` | MOCKED | Registers zero handlers → can never execute |
| `core/gateway/tool_gateway.py` | `:55-165` | EXISTS | Real execution + `EvidenceItem` — but **unused** in the pipeline |
| `PlaywrightBrowserController` | `core/browser/playwright_controller.py:111-119` | EXISTS | Wired at `pipeline_orchestrator.py:990-1003` |
| `ToolExecutionResult` contract compliance | — | **MISSING** | Pipeline **does not import** `core.contracts.task_contracts`; active contract is `ToolExecutionMeta` (`hunter_ai/pipeline/schemas.py:219-235`) |
| Tool failure recording | `pipeline_orchestrator.py` (15 sites) | MISSING | Every call sits inside `except Exception: logger.debug(...)` → failures are never logged as coverage gaps or evidence |

**Tools that actually execute:** subfinder, assetfinder, gobuster_dns, amass, theharvester, subzy, nmap, waybackurls, katana, hakrawler, gau, ffuf, feroxbuster, gobuster, dirsearch, nuclei, dalfox, nikto, sqlmap (via skills).
**Declared tools that never execute:** httpx (falsely credited — probing is done internally in Python), wpscan, arjun, trufflehog, shodan, naabu, ssrfmap, burp_scanner.

### 4.4 Local Models and AI Layer

| Component | Path | Verdict | Evidence |
|---|---|---|---|
| Ollama wrapper + Triad | `models/local/*.py`, `hunter_ai/brain/local_triad_agent.py:228-275` | EXISTS | Real `POST /api/chat` calls |
| AI Preflight Gate | `hunter_ai/brain/ai_preflight.py:132-357` | PARTIAL | Accepts any non-empty string as proof of inference (`:226-227`); called on only one path |
| Cognitive Council | `hunter_ai/brain/cognitive_council.py:318-361` | PARTIAL | Real calls, but when Ollama is down it fabricates a `HEURISTIC_PASS` vote (`:533-541`) that appears in reports as a model vote |
| Claude Thinking Protocol | `core/cognitive/claude_thinking_protocol.py:257-302` | **MOCKED** | Pre-written "thinking" strings with zero model calls; module is not wired to any entry point |
| `core/model_council.py` | `:132-182` | **MISSING (dead code)** | Zero callers; mentioned only in `WORKFLOW.md:96` |
| Model Router (task-based routing) | `hunter_ai/brain/model_router.py:70-137` | MOCKED | Real routing function, but its sole consumer logs the name and uses hardcoded strings |
| ⚠️ **Air-gapped environment claim** | `core/ai_reasoning_core.py:24-30` · `core/smart_orchestrator.py:229-272` | **Contradicts reality** | `.env` contains an active `GEMINI_API_KEY`; code tries cloud **before** local and sends `html_source[:2500]` and tool outputs to Google |

### 4.5 Scope, Policy, and Governance (Highest-Risk Area)

| Component | Path | Verdict | Evidence |
|---|---|---|---|
| Hard invariants (loopback/metadata/RFC1918) | `core/scope_engine.py:31-66` | EXISTS | `INVIOLABLE_IPV4_SUBNETS` + `HARD_BLOCKED_HOSTS` |
| Invariant evaluation function | `core/scope_engine.py:191-228` | EXISTS | Rejects inviolable networks before any allowlist rule |
| `StrictScopeEngine` | `core/scope_engine.py:230-326` | PARTIAL | No allowlist ⇒ allow all (`:311-312`) |
| `ScopeGuard` (second implementation) | `core/scope_guard.py:86-134` | PARTIAL | Zero loopback/metadata checks |
| `NetworkScopeGuard` (transport-level firewall) | `core/network_scope_guard.py:30-159` | **MOCKED** | `httpx` hooks defined but never installed on any production client; called in tests only |
| `PolicyGate` | `core/control_plane/policy_gate.py:70-177` | PARTIAL | Skips scope check for terminal commands (`:137-141`) |
| Destructive command blocker | `policy_gate.py:88-91` · `core/system/terminal_bridge.py:24-31` | PARTIAL | Substring denylist (6 patterns) |
| Operator approval for mutations | `core/policy/policy_as_code.py:91-140` | PARTIAL | Valid logic but outside the live execution path |
| Rate limiter (token bucket) | `core/rate_limiter.py:46-210` | EXISTS | Real implementation |
| Rate limiter enforcement | `pipeline_orchestrator.py:838,1095` | PARTIAL | Only 2 call sites; absent from all shell and tool paths |
| Emergency kill switch | `core/safety/kill_switch.py:33-81` | PARTIAL | Checked in only 1 place (`core/brain/autonomous_brain.py:1728`) |
| Constitutional layer P0-P4 | `core/safety/constitutional_layer.py:31-77` | PARTIAL | String prefix matching (`"169.254."`, `"127.0.0.1"`) |
| `hunter.yaml` (scope/limits/approvals) | `hunter.yaml:6-24` | **MISSING** | `--config` is never read anywhere (`cli/hunter_cli.py:105`) |
| `config/settings.yaml` permissions | `config/settings.yaml:28-33` | **MOCKED** | `unrestricted_scope: true` and `auto_approve_all: true` with no reader in code |
| Denied-command audit log | `core/control_plane/computer_control.py:88-95` | PARTIAL | Sole file writer; no audit `*.jsonl` exists in the repo tree |
| Invariant tests (loopback/metadata) | `tests/test_scope_and_false_positives.py` | **MISSING** | File only tests domain filtering; invariant tests live elsewhere |

#### Live Security Experiments (Not Inferred)

**Experiment 1 — PolicyGate allows cloud metadata access via terminal command:**

| Request | Category | Result |
|---|---|---|
| `nmap -sV 8.8.8.8` (out of scope, `target=local_terminal`) | `terminal_command` | ✅ **Allowed** |
| `curl http://169.254.169.254/latest/meta-data/` | `terminal_command` | ✅ **Allowed** |
| `rm -rf / --no-preserve-root` | `terminal_command` | ❌ Denied |
| `http://evil.example.net/` | `http_request` | ❌ Denied (out of scope) |
| `http://example.com/` | `http_request` | ✅ Allowed |

Root cause: `policy_gate.py:137-139` treats any terminal command with an empty `target` or `local_terminal` as local execution, skipping scope validation entirely — and the `169.254.169.254` check lives inside that skipped branch. Thus the "inviolable" metadata block is bypassed via terminal commands — the exact behavior certification gate `GATE-11` claims to verify.

**Experiment 2 — `--scope-file` crashes the entire pipeline:**
```
AttributeError: type object 'StrictScopeEngine' has no attribute 'from_file'.
  at hunter_ai/pipeline/pipeline_orchestrator.py:178
```
`from_file` does not exist (only `from_yaml:129` and `from_dict:145` exist), and `max_rate_limit_rps` passed at `:183` is not a field on `ScopePolicy`, so it is silently dropped (verified live).

#### Confirmed Security Gaps

| # | Gap | Evidence |
|---|---|---|
| S1 | **All pipeline tool execution runs without any policy gate, scope check, or rate limit** | `hunter_ai/pipeline/tool_specs.py:741,766` → `tools/tool_manager.py:224` |
| S2 | **Scope gate bypassed for terminal commands** (Experiment 1) | `core/control_plane/policy_gate.py:137-141` + `computer_control.py:121,220` |
| S3 | **Hard invariants bypassed via alternate IP encodings** (`localhost.`, `127.1`, `2130706433`, `0x7f000001`) — no DNS resolution | `core/scope_engine.py:196-222` then `:311-312` (default allow) |
| S4 | **Out-of-scope leakage via `<script src>` tags** — filtering applies to links, not scripts; `googletagmanager.com` is the test case in the repo itself | `pipeline_orchestrator.py:1040-1042, 1102, 1105-1108, 1305` |
| S5 | **Scope stage makes a network request before rejecting** | `pipeline_orchestrator.py:552` then rejection at `:582` |
| S6 | **Four divergent scope implementations and two classes named `PolicyEngine`** — one defaults to wide open | `core/gateway/policy_engine.py:33,36,40` (`full_permissions=True`, `target="*"`, `max_repeated_actions=99999`) |
| S7 | **`ToolRouter` gate silently disabled** — wrong kwargs followed by `except: pass` | `hunter_ai/tools/tool_router.py:151-162` |
| S8 | **Two capability interfaces with zero policy checks** (arbitrary argv execution + `httpx` GET with `verify=False`) | `core/capabilities/computer_skill.py:77,104` |

### 4.6 Memory, Shared State, and Event Bus

| Component | Path | Verdict | Evidence |
|---|---|---|---|
| **Single shared investigation state** | — | **MISSING** | Four disconnected blackboard classes (below); `main.py:117` imports none of the 5 memory stores |
| `ThreeTierBlackboardMemory` | `hunter_ai/brain/agent_manager.py:64` | EXISTS | Writes `:108,152,180`, reads `:137,172,188` |
| `MemoryHierarchy` | `hunter_ai/brain/memory_hierarchy.py:22` | PARTIAL | 4 real directories, but default root is `tempfile.mkdtemp` (`:32`) ⇒ no recovery across restarts |
| `MemoryManager` v2 | `core/system/memory_manager_v2.py:188` | PARTIAL | `ProjectMemory.storage_path` is never used to save (`:88-90`) |
| SI memory (4 files) | `agents/security_intelligence/memory_manager.py:21` | MOCKED | `persist=False` by default and zero `persist=True` in the repo ⇒ every `_save` returns immediately |
| `FailureMemory` (anti-repetition) | `core/memory/failure_memory.py:37` | EXISTS | Loads on start `:50-65`, writes `:104`, reads `:117-129`, wired at `pipeline_orchestrator.py:207` |
| Active anti-repetition half | `core/decision_core.py:84-153` | PARTIAL | `record_failure` is called only in `certify.py:510`; production only calls `record_rejected_hypothesis` ⇒ blocking never triggers |
| `BrowserEventBus` | `core/browser/browser_event_bus.py:51` | PARTIAL | Producer wired (`core/browser/session.py:220-224`); sole consumer is instantiated only in tests ⇒ **zero real consumers** |
| `BurpEventBus` + `SecurityEventBus` | `agents/burp_agent/pipeline/event_bus.py:26` · `agents/security_intelligence/events.py:64` | EXISTS | Real producers and consumers + adapter at `core/integration/security_intelligence_adapter.py:54-60` |
| Crash recovery | — | PARTIAL | Only `MissionState` and `failure_memory.json`; each run creates a new timestamped directory (`engagement_manager.py:84-87`) |
| Secret sanitization before write | `core/secret_sanitizer.py:12` | PARTIAL | Applied only at `pipeline_orchestrator.py:422-423`; bypassed in `save_tool_artifact` |
| `BlackboardState` (claimed "single source of truth") | `hunter_ai/brain/orchestrator_workers.py:73` | MOCKED | In-memory; `save_json:143` never called; contents are hardcoded values (`:500-501,511-512,521,525,550-552`) |
| Orchestrator blackboard | `core/orchestrator.py:250,273-275` | **MOCKED (broken)** | Calls nonexistent `create_job()` and `add_evidence(url=)` with mismatched signature ⇒ raises exception; class is never instantiated |

#### Confirmed Memory Gaps

| # | Gap | Evidence |
|---|---|---|
| M1 | **No shared investigation state** — 6 parallel stores do not read one another, and the live scan path imports none of them | `pipeline_orchestrator.py:29-84` |
| M2 | **`core/brain/autonomous_brain.py` — the brain itself — has zero references to any blackboard or memory** | Zero matches for `blackboard|Memory(` in the file |
| M3 | **Synthetic experience memory**: records `SUCCESS_CONFIRMED` regardless of actual response | `core/orchestration/investigation_loop.py:133-134,138,160,183-186` |
| M4 | **Plaintext secret leakage into engagement artifacts**: raw values passed to `record_lineage`, then written unsanitized to `timeline.json`, `run.log`, and `lineage_graph.json` | `pipeline_orchestrator.py:1320` → `engagement_manager.py:229,201,174` |
| M5 | **Unsanitized raw tool outputs** in `*.raw.txt` and `data/tool_outputs/*.txt` | `tool_specs.py:782` · `tools/tool_manager.py:135-151` |
| M6 | **Raw HTTP headers and cookies stored in SQLite** | `core/browser/traffic_bridge.py:131,170-179` |
| M7 | **`data/memory/*.json` files have no reachable writer** — stale artifacts from an earlier version | `agents/security_intelligence/config.py:30-33` |
| M8 | **Import-time side effects**: 6 modules create directories/databases merely on import | `experience_store.py:17` and siblings |

### 4.7 Evidence Court and Graphs — Details

| Component | Path | Verdict | Evidence |
|---|---|---|---|
| `EvidenceCourt` v1 (reference) | `core/evidence_court.py:151-389` | EXISTS | Ordered gates: scope `:187` → WAF `:198` → negative evidence `:212` → contradiction `:252` → reflection `:267` → length/status diff `:300` → triad `:314`; confirmation only at `:345` |
| Hard qualification gate in pipeline | `hunter_ai/pipeline/qualification_gate.py:125` | EXISTS | `if judgment.verdict != CourtVerdict.CONFIRMED: return False, …` |
| **"Deterministic proof" criterion** | `core/evidence_court.py:331-343` | **MOCKED** | `has_deterministic_proof` = any truthy caller-supplied value; no proof engine invoked |
| `ProofOfExecutionEngine` | `core/poe_engine.py:19-52` | EXISTS | Real regex rejecting reflected `$((53+19))` and requiring isolated `72` |
| **Wiring PoE to court/pipeline** | — | **MISSING** | Imported only in `run_unified_live_session.py:65` and tests; zero imports under `hunter_ai/` |
| `EvidenceCourtV2` | `core/court/evidence_court_v2.py:62-147` | MOCKED | All inputs are caller booleans `:70-74`; FINDER vote hardcoded to `VOTE_CONFIRM` `:79-84` |
| `EvidenceOS.rule_verdict` | `core/evidence_os/unified_model.py:242` | MOCKED | Defaults to `decision="CONFIRMED"`; tested live: `has_execution_proof=False` ⇒ **CONFIRMED** |
| `ArbitrationEngine` | `core/arbitration_engine.py:75-99` | PARTIAL | `is_verified = tool_output.get("verified", False)` ⇒ `CONFIRMED` |
| `ConfidenceChecker` | `core/confidence_checker.py:474-522` | MOCKED | Two fabricated model votes ≥0.65 ⇒ `CONFIRMED 0.9` (executed) |
| `HunterFinding` — default values | `hunter_ai/pipeline/schemas.py:199-202` | MOCKED | Schema defaults to `status = FindingStatus.CONFIRMED` and `tier = VERIFIED_FINDING` |
| `EvidenceGraph` (v1) | `core/evidence_graph.py:190` | PARTIAL | Written to `13_evidence/evidence_graph.json` (`pipeline_orchestrator.py:2139`) and **never read** |
| `AttackSurfaceGraph` | `core/attack_surface_graph.py:76-122` | MOCKED | In-memory only (`self.nodes`) |
| `AttackSurfaceGraph` (reasoning) | `core/reasoning/attack_surface_graph.py` | MISSING | No persistence, no JSON, no SQLite |
| `EvidenceLedger` | `core/evidence_ledger.py:29-61` | PARTIAL | In-memory chain; hash includes `time.time()` (`:47`) ⇒ non-verifiable |
| Reflection/noise/WAF tests | Multiple | PARTIAL | All pass, but test caller-supplied flag combinations rather than live responses; `BLOCKED` branch is **completely untested** |

#### Confirmed Court Gaps

| # | Gap | Evidence |
|---|---|---|
| C1 | **Verdict is effectively caller-controlled** — `{"reproduced":True,"deterministic_proof":"anything"}` ⇒ CONFIRMED (executed) | `core/evidence_court.py:333-342` |
| C2 | **Two courts with contradicting axioms**: V1 rejects "length diff only", while V2 accepts it because the caller converts byte diff into `proof_nonce_proven=True` | `core/evidence_court.py:300` vs. `core/brain/autonomous_brain.py:2297` |
| C3 | **Free-text "proof"**: `"72" in reason` and `"reflection" in reason` treated as evidence | `core/brain/autonomous_brain.py:2263-2267` |
| C4 | **Sensor signals default to `True`** ⇒ `agreement_ratio=1.0` ⇒ hollow confirmation | `core/brain/autonomous_brain.py:2459-2460` → `core/scoring/tool_agreement.py:59-61` |
| C5 | **Reflection confirms XSS**: `has_xss_exec = … and probe in probe_resp.text` (mere echo) | `core/smart_probe_engine.py:370,381`; similarly `core/independent_verifier.py:69-72` |
| C6 | **`EvidenceOS.rule_verdict` defaults to CONFIRMED** and skips lineage validation | `core/evidence_os/unified_model.py:242,251` |
| C7 | **Direct writes of CONFIRMED bypass all gates** | `investigation_controller.py:638` (live path), `pipeline_orchestrator.py:1810…2087` (dead), `schemas.py:199` |
| C8 | **Tautology bug**: `x.lower() in x.lower()` makes length difference alone sufficient | `core/evidence_graph.py:267` |

### 4.8 Tests

| Component | Path | Verdict | Evidence |
|---|---|---|---|
| Test suite size | `tests/` | EXISTS | **186 files**, **1129 test functions** |
| Full run | `python -m pytest tests` | PARTIAL | 1052 passed / 12 failed / 5 files failed to collect (7m 52s) |
| **Hard qualification gate** | `hunter_ai/pipeline/qualification_gate.py` | **MISSING** | **Zero** test files reference it — the most critical gate in the system is untested |
| **P0 contracts** | `core/contracts/task_contracts.py` | **MISSING** | **Zero** test files reference it |
| `core/poe_engine.py` | — | PARTIAL | Only 1 test file; no test verifies wiring to any production path |
| `core/teams/*` | `tests/test_agent_teams_benchmark.py` | MOCKED | Sole file, **not collectible by pytest** (no `test_*`), and fails 3/10 when run directly |
| Findings count assertion | `tests/test_hunter_master_pipeline.py:306,342` | MISSING | Checks `status == "completed"` and file existence only; **never checks `findings_count`** ⇒ no test can detect zero findings |
| WAF/`BLOCKED` branch test | `core/evidence_court.py:198` | MISSING | No test sets `is_blocked_by_waf` or `waf_blocked` |
| Reflection/noise tests | `tests/test_evidence_driven_system.py:44-59` and siblings | PARTIAL | Pass, but test flag combinations supplied by the test rather than live responses |
| Scope invariant tests | `tests/test_scope_and_false_positives.py` | MISSING | Only tests domain filtering; no loopback/metadata/RFC1918 checks |

#### Breakdown of the 12 Failures (Grouped by Root Cause)

| Root Cause | Count | Files | Significance |
|---|---|---|---|
| `ImportError: CoverageStatus` (from `core/brain/autonomous_brain.py:1734`) | 5 | `test_autonomous_brain_state`, `test_integration_pipeline`, `test_program_intelligence_and_triad`, `test_v19_epistemic_security_os` (2) | Commit `af1af9c` regression breaks the entire `AutonomousBrain` path |
| `'aborted' == 'completed'` | 5 | `test_artifact_based_recon`, `test_enterprise_casm` (2), `test_hunter_master_pipeline` (2) | Aborted due to AI Preflight failure (no Ollama on this machine) — **environmental** |
| `'ai_preflight_failed' == 'out_of_scope'` | 2 | `test_enterprise_casm::test_orchestrator_invariant_abort_on_loopback`, `test_hunter_workflow_pipeline::test_orchestrator_scope_rejection` | **Not environmental**: exposes inverted gate order. With Ollama present, these tests would pass **by accident** and hide the bug |

**Governing observation:** The test matrix is large (1129 functions) but **does not guard architectural invariants**: the two most critical new gates (`qualification_gate`, `task_contracts`) have zero coverage, and no test checks whether the system actually finds a vulnerability. That is why 15/15 certification gates pass while real runs yield zero findings.

---

## 5. Prioritized Confirmed Gaps (Unified List)

### P0 — Prevents the System from Operating Reliably

| # | Gap | Evidence | Source |
|---|---|---|---|
| 1 | **Court trusts caller flags** — completely fabricated claim is confirmed | Documented experiment §1; `core/evidence_court.py:331-343` | C1 |
| 2 | **Confirmation path bypasses the court completely** (`_promote_to_evidence_court` never calls the court) | `hunter_ai/pipeline/investigation_controller.py:632-668` | C7 |
| 3 | **Pipeline never produces a confirmed finding** (6 call sites pass `reproduced` only) | `pipeline_orchestrator.py:711,1283,1613,1641,1667,1782` | §1 |
| 4 | **Entire verification block is dead code** (340 lines) | `pipeline_orchestrator.py:1558` vs. `:1793` | §1 |
| 5 | **PoE engine is unwired from any production path** | Imported only in `run_unified_live_session.py:65` | §4.7 |
| 6 | **Two courts with contradicting axioms** — V2 accepts what V1 rejects | `autonomous_brain.py:2297` vs. `evidence_court.py:300` | C2 |
| 7 | **Security guardrails bypassed via terminal commands** — `curl 169.254.169.254` allowed (executed) | `core/control_plane/policy_gate.py:137-141` | S2 |
| 8 | **All pipeline tool execution lacks policy/scope/rate-limit checks** | `tool_specs.py:741,766` → `tool_manager.py:224` | S1 |
| 9 | **Security gate runs after AI gate** — out-of-scope target returns `ai_preflight_failed` | `pipeline_orchestrator.py:2359-2371` | §1 |
| 10 | **Environment is not air-gapped**: active Gemini key, cloud tried before local, target data sent externally | `core/ai_reasoning_core.py:24-30` · `.env` | §4.4 |
| 11 | **CLI completely broken** — 68 commands dead | `cli/hunter_cli.py:50` | §3 |
| 12 | **`--scope-file` crashes pipeline** with `AttributeError` (executed) | `pipeline_orchestrator.py:178` | Exp 2 |
| 13 | **Unified contract unwired from pipeline** — three parallel contracts | `pipeline_orchestrator.py:29-84` · `schemas.py:219-235` | §4.3 |
| 14 | **No shared investigation state** — 6 separate stores that never read each other | `pipeline_orchestrator.py:29-84` | M1 |
| 15 | **Plaintext secret leakage into engagement artifacts** without sanitization | `pipeline_orchestrator.py:1320` → `engagement_manager.py:229,201,174` | M4 |
| 16 | **Tool failures silently swallowed** at 15 call sites and never logged as coverage gaps | `pipeline_orchestrator.py:613…1707` | §4.3 |
| 17 | **Dangerous defaults**: `HunterFinding.status=CONFIRMED` by default, and `EvidenceOS.rule_verdict` defaults to CONFIRMED | `schemas.py:199` · `evidence_os/unified_model.py:242` | C6, C7 |

### P1 — Prevents Genuine Agent Collaboration

| # | Gap | Evidence |
|---|---|---|
| 18 | **`core/teams` is completely dead code** — only imported by a benchmark script | `core/teams/__init__.py:12` + full scan: zero production callers |
| 19 | **18 team agents cannot execute anything** — zero network/subprocess imports, hardcoded data | `recon_team.py:46-58` and siblings |
| 20 | **Team reviewers rubber-stamp their own team's data and write it to the coverage ledger** | `recon_team.py:134,142-148` |
| 21 | **Independent review broken in scheduler** (self-review guard bypassed) | `core/system/task_scheduler.py:275-277` vs. `:168-170` |
| 22 | **`EvidenceCourtReviewer` approves UNVERIFIED** — executed: `review()` returns `True` with note "Verdict: UNVERIFIED" | `core/teams/verification_team.py:181,188` |
| 23 | **`TaskScheduler.add_task()` lacks `parameters`** ⇒ every verification task silently becomes IDOR | `task_scheduler.py:84-95` · `verification_team.py:105,178,179` |
| 24 | **`subagent_manager_v2.launch_subagent` runs nothing** | `core/system/subagent_manager_v2.py:87-141` |
| 25 | **Fabricated outputs displayed to users** in `hunter swarm` and web UI | `cli/hunter_cli.py:630-632` · `ui/web/app.py:1636-1640` |
| 26 | **`hunter_ai/brain/orchestrator_workers.py` injects fabricated state** (hardcoded strings and results) | `:500-512,521,525,550-552` |
| 27 | **`CognitiveCouncil` fabricates `HEURISTIC_PASS` votes when Ollama is down** and writes them to reports | `cognitive_council.py:533-541` → `pipeline_orchestrator.py:1520` |
| 28 | **`BrowserEventBus` has zero production consumers** | `browser_event_bus.py:51` · `browser_brain_loop.py:91` (tests only) |
| 29 | **`EvidenceGraph` is written and never read**; attack surface graphs are in-memory only | `pipeline_orchestrator.py:2139`; `attack_surface_graph.py:76-122` |
| 30 | **Synthetic experience memory** — always logs success | `core/orchestration/investigation_loop.py:133-186` |
| 31 | **No coverage ledger in pipeline** — zero usage of `CoverageLedger` | `pipeline_orchestrator.py` |
| 32 | **`BurpRepeaterController` fabricates responses locally** then saves them as differential experiments | `core/controllers/burp_controller.py:80-84` → `pipeline_orchestrator.py:1535-1550` |
| 33 | **`crtsh` adapter reports false success** (exit 127 with `status="success"`) | `tool_specs.py:109,730,764-770` |
| 34 | **`httpx` credited as executed when it never ran** | `pipeline_orchestrator.py:890,933` |
| 35 | **Four scope implementations and two `PolicyEngine` classes**, one wide-open by default | `core/gateway/policy_engine.py:33,36,40` |
| 36 | **Invariants bypassed via alternate IP encodings** (`127.1`, `2130706433`, `0x7f000001`) | `core/scope_engine.py:196-222` then `:311-312` |

### P2 — Hygiene and Consistency

| # | Gap | Evidence |
|---|---|---|
| 37 | Running tests and `certify.py` mutates git-tracked files (no isolation) | `PRE_KALI_CERTIFICATION.md` + 6 databases |
| 38 | `docs/IMPLEMENTATION_STATUS.md` lags behind the code | States Phases 2–17 have not started while they already exist |
| 39 | `config/models.yaml`, `model_manifest.json`, and `hunter.yaml` have no reader | Zero callers |
| 40 | `config/settings.yaml` declares `unrestricted_scope: true` and `auto_approve_all: true` with no reader | `config/settings.yaml:28-33` |
| 41 | Hardcoded Ollama host `192.168.1.3` in 6 locations despite claiming `127.0.0.1` | `orchestrator_workers.py:155` and siblings |
| 42 | Pipeline tests assert structure only, never `findings_count` | `tests/test_hunter_master_pipeline.py:306,342` |
| 43 | Obsolete/duplicate files: 0-byte `python nvidia_test.py` and re-export `core/terminal_bridge.py` | — |
| 44 | `core/tool_registry.py:211` uses unimported `Tuple` ⇒ `NameError` when invoked | `core/tool_registry.py:12,211` |

---

## 6. What Is Real and Must Be Preserved (Do Not Rebuild)

1. **`ToolManager`** — Subprocess execution with timeout and output persistence: `tools/tool_manager.py:224-259`.
2. **`EvidenceCourt` v1 logic itself** — Ordered, logically sound gates: `core/evidence_court.py:186-389`. The flaw is in its *inputs*, not its decision sequence.
3. **`core/poe_engine.py:19-92`** — Real arithmetic proof engine that rejects reflection. The only issue is that it is not wired in.
4. **`agents/skills/*`** — 14 skills making real `httpx` requests with genuine mutation and comparison logic.
5. **`agents/recon_agent.py` + `web_agent.py`** — Real tool execution with stdout parsing and tool-availability filtering.
6. **`CoverageLedger`** — Real accounting structure with JSON persistence: `core/coverage/coverage_ledger.py:86-271`.
7. **`ToolExecutionResult`/`TaskContract` contracts** — Sound design and implementation: `core/contracts/task_contracts.py:76-210`.
8. **`run_unified_live_session.py`** — Working E2E harness that produces a confirmed verdict via a complete metamorphic triad.
9. **`core/detectors/{sqli,xss}_detector.py`** — Passes proof flags derived from actual observations (`sqli_detector.py:100-104`).
10. **`CounterexampleAgent` and `ReproductionAgent`** — Real refutation logic and real re-execution (`verification_team.py:40-95`).
11. **`core/rate_limiter.py:46-210`** — Real token bucket with backoff and circuit breaker.
12. **`core/scope_engine.py:31-66,191-228`** — Hard invariants and their evaluation logic are sound — they just need enforcement across all paths.
13. **Real Burp layer**: `CaptureStore` + `SecurityEventBus` + `UnifiedEvidenceStore` have real producers and consumers.

---

---

## 8. Extended Classification Matrix (Session 2 Update)

The official project plan uses **7 statuses**. The original audit used 5; this section adds `DISCONNECTED` and `BLOCKED` and records baseline changes.

### 8.1 Baseline State (Re-Measured Live)

| Metric | Round 1 | Current Session | Reason |
|---|---|---|---|
| Collected by pytest | 1064 | **1129** | Fixed `CoverageStatus` regression |
| Collection errors | 5 files | **0** | Same fix |
| Failures | 12 | **5** then **0** | 5 were a code regression; 7 depended on Ollama availability |
| Ollama | Unavailable during measurement | **Available: 5 models** | `qwen3:8b`, `qwen2.5-coder:14b`, `qwen2.5-coder:14b-tools`, `xploiter/pentester:latest`, `WhiteRabbitNeo/Llama-3.1-...` |
| AI Preflight | — | **`online=True, inference_ok=True, 3/3 roles`** | Verified directly |
| Installed external tools | `nmap` only | `nmap` only | Rest missing |

> **Recorded correction:** Classifying 5 failures as "environmental" was accurate at that moment, but it was **not the complete root cause**. Once Ollama became available, 5 real failures remained, all stemming from a single regression. Governing rule: re-measure directly rather than relying on prior narratives.

### 8.2 `DISCONNECTED` — Implementation Exists but Is Not Wired into the Workflow

| Component | Path | Why Disconnected |
|---|---|---|
| `core/teams` (18 agents) | `core/teams/__init__.py:12` | Zero production callers; only a benchmark script. Bodies themselves are `MOCKED` |
| `ProofOfExecutionEngine` | `core/poe_engine.py:19-92` | Imported only in `run_unified_live_session.py:65` and tests |
| `core/gateway/tool_gateway.py` | `:55-165` | Real governed execution + `EvidenceItem`; never called by pipeline |
| `core/network_scope_guard.py` | `:30-159` | `httpx` hooks never installed on any production client |
| `core/blackboard/agent_blackboard.py` | `:42-80` | Real knowledge namespaces with zero production callers |
| `core/normalizer/tool_normalizer.py` | `:62-120` | Real JSON parser; called only by previously broken CLI and `autonomous_brain` |
| `core/ai_bridge/*` | `hybrid_ai_router.py:83-159` | Full cloud router unwired from any entry point |
| `core/cognitive/claude_thinking_protocol.py` | `:257-302` | Canned strings + unwired |
| `core/model_council.py` | `:132-182` | Zero callers |
| `hunter_ai/tools/tool_router.py` | `:96-104` | Registers zero handlers ⇒ cannot execute; its gate is silently disabled |
| `core/policy/policy_as_code.py` · `core/safety/constitutional_layer.py` | `:91-140` · `:31-77` | Valid logic outside the live execution path |
| `core/reasoning/attack_surface_graph.py` | — | In-memory only, no persistence |
| `BrowserEventBus` | `core/browser/browser_event_bus.py:51` | Producer wired; sole consumer is instantiated in tests |
| `EvidenceGraph` | `pipeline_orchestrator.py:2139` | Written to `13_evidence/evidence_graph.json` and never read |
| `httpx` spec in tool registry | `hunter_ai/pipeline/tool_specs.py:136-149` | Actual probing runs internally in Python; binary never invoked |
| `ToolExecutionResult` | `core/contracts/task_contracts.py:76-117` | Not imported by pipeline (which uses `ToolExecutionMeta`) |

### 8.3 `BLOCKED` — Verification/Execution Blocked on Unavailable Dependency

| Component | Missing Dependency | Verification Performed |
|---|---|---|
| `subfinder`, `httpx`, `nuclei`, `ffuf`, `gobuster`, `katana`, `sqlmap`, `dalfox`, `amass` | Not installed on this host (`Get-Command` = missing) | Fallback path works; 7 coverage gaps now recorded |
| Live Burp agent via proxy | Nothing listening on `127.0.0.1:8080` | Direct TCP check ⇒ NOT LISTENING |
| Certification gates relying on Kali tools | Same tools above | `certify.py` passes 15/15 because it never executes the tools |

> Note: `nmap` is the only external security binary installed. Browser automation paths work: `firefox` and `chromium` launched via Playwright (`LAUNCH OK` for both), and `run_unified_live_session.py` passes end-to-end — so browser automation is `EXISTS`, not `BLOCKED`.

### 8.4 Changed from `MISSING` to `EXISTS` in This Session

`CoverageStatus` · `StrictScopeEngine.from_file` · scope gate ordering · tool failure classification · coverage gap recording.

Full details and evidence are in `docs/IMPLEMENTATION_LEDGER.md`.

---

## 7. Mapping to Phase 1 Plan

| Plan Priority | Required Action Based on This Audit |
|---|---|
| **P0 — Implementation audit** | ✅ Completed by this report |
| **P0 — Contract unification** | Eliminate duplicate contracts: standardize on `ToolExecutionResult`, turn `ToolExecutionMeta` into an adapter delegating to it, and wire it into `MasterToolRegistry` and every agent |
| **P0 — Task Scheduler** | Fix self-review bypass (`task_scheduler.py:275`), add `parameters`, and stop `Simulated noop` from passing as success |
| **P0 — Coverage measurement** | Wire `CoverageLedger` into `HunterPipelineOrchestrator` and record every tool failure as a blindspot instead of swallowing it |
| **P0 — Close verification loophole** | Make proof **derived**, not **declared**: feed actual requests/responses into `ProofOfExecutionEngine` instead of trusting caller flags. Highest-priority item on the list |
| **P1 — Recon/Web Teams** | Rebuild `core/teams` to consume real `MasterToolRegistry`, or delete it and build teams on top of real `agents/` |
| **P1 — Adaptive Planner** | Wire `InformationGainPlanner` to real `hypotheses` instead of constants |
| **P1 — Independent Verification** | Make `EvidenceCourt` mandatory on **every** path writing `CONFIRMED`, and remove direct writes |
| **P1 — Persistent State** | Select a single shared-state store and wire it into the `main.py` path |
| **Before all else** | Fix the `CoverageStatus` regression (restores CLI and 5 test files) and order scope gates before AI preflight |
