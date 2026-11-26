# Agent Skills Guide

**Language:** English · **Purpose:** Documents all added skills, how the agent reasons and selects tools, core concepts, and the autonomous workflow.

---

## Table of Contents
1. [Skills Concept and Categories](#1-skills-concept-and-categories)
2. [How the Agent Thinks (4-Step ReAct Loop)](#2-how-the-agent-thinks-4-step-react-loop)
3. [How the Agent Uses Tools (Tool Planner)](#3-how-the-agent-uses-tools-tool-planner)
4. [Full Skills List (42 Skills)](#4-full-skills-list-42-skills)
5. [Technical Details for New Skills](#5-technical-details-for-new-skills)
6. [Dynamic Skill Registry](#6-dynamic-skill-registry)
7. [Autonomous Loop](#7-autonomous-loop)
8. [Hunt Memory (/remember and /memory-gc)](#8-hunt-memory-remember-and-memory-gc)
9. [LLM Brain](#9-llm-brain)
10. [Recommended End-to-End Workflow](#10-recommended-end-to-end-workflow)
11. [Quick Code Examples](#11-quick-code-examples)
12. [Adding a New Skill (Template)](#12-adding-a-new-skill-template)
13. [Core Rules (Always Active)](#13-core-rules-always-active)

---

## 1. Skills Concept and Categories

All agent skills under `skills/` inherit from `BaseSkill` and implement `execute(ctx)`. Each skill directory contains:
- `skill.py`: execution logic.
- `skill.yaml`: metadata (category, required tools, fallbacks, timeout, next skills).
- `__init__.py`: module exports.

Core categories:
| Category | Purpose |
|----------|---------|
| `agent_core` | Reasoning, tool planning, exploit chaining, autonomous loop, memory, LLM assistance |
| `recon` | Subdomain enumeration, live host discovery, ports, tech fingerprinting, WAF detection, hidden parameters |
| `web` | IDOR, SSRF, safe SQLi, reflected XSS, 403/401 bypass |
| `analysis` | Attack surface ranking, business logic flaws, subdomain takeover, secrets, cloud exposure |
| `web3` | Token rug-pull scanning, smart contract auditing |
| `reporting` | Final report generation |
| `browser` | Browser control, network and behavior analysis |

---

## 2. How the Agent Thinks (4-Step ReAct Loop)

`agent_reasoning_loop` implements a 4-step **ReAct** (Reason + Act) cycle, logging every step to `thinking_trace.json`:

### Step 1 — Observe
The agent reads:
- Target and current phase (`recon`, `scan`, `analyze`, `exploit`, `report`).
- Installed and available tools via `ToolManager`.
- Findings logged so far.
- Notable response signals (`id=`, `url=`, `price=`, `.env`, `admin`, `swagger`, …).

### Step 2 — Think
Applies impact-first priority rules (per `AGENTS.md`):
- Sequential identifiers (`id=`, `user_id=`, `order=`) → `idor_tester`.
- External URL parameters (`url=`, `callback=`, `webhook=`) → `ssrf_hunter` or crawl with `katana`.
- Financial parameters (`price=`, `coupon=`) → `logic_flaw_hunter`.
- Sensitive files (`.git/`, `.env`, `config`) → `secrets_hunter`.
- Subdomain takeover indicators → `takeover_confirm`.
- `recon` phase with no prior evidence → starts with `subfinder`, then `httpx`.

If an LLM is provided via `ctx.extra["llm"]`, `agent_llm_brain` enriches the decision with a text rationale; otherwise, `reasoning_loop` and `llm_brain` run fully **offline** using heuristics.

Output: `confidence` (0–1) + `next_tool`/`next_skill` + `reasoning` + `next_skills`.

### Step 3 — Act
Turns the decision into a concrete action: the selected tool plus suggested follow-up skills. If confidence is `≥ 0.7`, it logs a preliminary finding for later review.

### Step 4 — Reflect
Evaluates the decision before execution:
- Is the tool intrusive (`sqlmap`, `ffuf`)? → warns to verify scope first.
- Is confidence low? → favors passive recon first.
- Output: `verdict` = `proceed` or `proceed_with_caution`.

Every cycle is persisted to `thinking_trace.json` so each decision can be audited later.

---

## 3. How the Agent Uses Tools (Tool Planner)

`agent_tool_planner` decides which tool to run, when, and in what order.

Selection logic:
1. **Phase:** `recon → scan → analyze → exploit → report`.
2. **Risk level:** Starts with `low` (passive, read-only), then `medium`. Uses `high` only when the operator approves (`max_risk: high`) and scope is authorized.
3. **Scope:** Checks `StrictScopeEngine` before selecting any active tool.
4. **Availability:** Picks the first installed tool; if missing, falls back to the registered alternative (e.g., `subfinder → amass → crt_sh → waybackurls`).
5. **Output:** `tool_plan.json` (full plan) and `next_tool.json` (next tool for immediate execution).

The agent never runs tools directly. It outputs only the tool name, and execution passes through `ToolManager` / `ToolRouter` under phase, risk, and scope gates.

---

## 4. Full Skills List (42 Skills)

Newly added skills by category:

### agent_core
| Skill | Path | Purpose |
|-------|------|---------|
| Reasoning Loop | `skills/agent_core/reasoning_loop/` | ReAct thinking loop that decides the next step |
| Tool Planner | `skills/agent_core/tool_planner/` | Selects the tool for each phase with safe fallbacks |
| Chain Builder | `skills/agent_core/chain_builder/` | Builds A→B→C exploit chains |
| Skill Registry | `skills/agent_core/skill_registry/` | Discovers skills from `skill.yaml` and runs them by name |
| LLM Brain | `skills/agent_core/llm_brain/` | Enriches decisions via LLM with offline heuristic fallback |
| Hunt Memory | `skills/agent_core/hunt_memory/` | Implements `/remember` and `/memory-gc` for hunt memory |
| Autonomous Loop | `skills/agent_core/autonomous_loop/` | End-to-end loop: plan → tool → validate → chain → report → memory |

### analysis
| Skill | Path | Purpose |
|-------|------|---------|
| Attack Surface Ranker | `skills/analysis/attack_surface_ranker/` | Ranks assets by value and exploitability |
| Logic Flaw Hunter | `skills/analysis/logic_flaw_hunter/` | Business logic flaws (pricing, coupons, verification bypass) |
| Takeover Confirm | `skills/analysis/takeover_confirm/` | Confirms subdomain takeovers via CNAME fingerprints |
| Secrets Hunter | `skills/analysis/secrets_hunter/` | Scans for leaked keys and credentials |
| Cloud Recon | `skills/analysis/cloud_recon/` | Discovers exposed public cloud buckets (S3, Azure, GCS) |

### web
| Skill | Path | Purpose |
|-------|------|---------|
| IDOR Tester | `skills/web/idor_tester/` | Tests sequential IDs via response comparison |
| SSRF Hunter | `skills/web/ssrf_hunter/` | Tests server-side request forgery parameters |
| SQLi Hunter | `skills/web/sqli_hunter/` | Read-only SQLi detection via differential comparison |
| XSS Hunter | `skills/web/xss_hunter/` | Reflected XSS detection using a unique marker |
| Bypass 403 | `skills/web/bypass_403/` | 403/401 bypasses (forged headers, alternate HTTP methods) |

### recon
| Skill | Path | Purpose |
|-------|------|---------|
| Param Discover | `skills/recon/param_discover/` | Discovers hidden HTTP parameters (arjun/paramspider/Wayback) |

### web3
| Skill | Path | Purpose |
|-------|------|---------|
| Token Scan | `skills/web3/token_scan/` | Detects rug-pull patterns in tokens |
| Web3 Audit | `skills/web3/web3_audit/` | Preliminary static audit for Solidity contracts |

Existing repository skills are also auto-discovered by the registry (`subdomain_enum`, `live_host_detection`, `port_scan`, `dns_enum`, `tech_detection`, `waf_detection`, `smb_enum`, `crawling`, `endpoint_discovery`, `js_analysis`, `parameter_discovery`, `api_surface_audit`, `cloud_metadata_audit`, `ssh_audit`, `tls_audit`, `perimeter_matrix`, `triage_gate`, `behavior_analysis`, `browser_recon`, `network_intelligence`, `form_intelligence`, `report_generator`).

---

## 5. Technical Details for New Skills

### 5.1 Reasoning Loop (`agent_reasoning_loop`)
- **Inputs:** `target`, `phase`, `findings_so_far`, `goal`.
- **Outputs:** `thinking_trace.json`, `next_action.json`.
- **Logic:** Observe → Think → Act → Reflect. Uses heuristics by default, with optional LLM enrichment.

### 5.2 Tool Planner (`agent_tool_planner`)
- **Inputs:** `target`, `phase`, `max_risk` (`low`|`medium`|`high`), `scope_authorized`.
- **Outputs:** `tool_plan.json`, `next_tool.json`.
- **Logic:** Filters by phase, risk level, scope authorization, tool availability, and fallback chains.

### 5.3 Chain Builder (`agent_chain_builder`)
- **Inputs:** `target`, `findings` (list of confirmed findings).
- **Outputs:** `exploit_chains.json`.
- **Example chains:** `subdomain_takeover → session_cookie_theft → Account takeover`, `ssrf → internal_network_access → metadata exposure`, `idor → data_exfiltration`.

### 5.4 Attack Surface Ranker (`attack_surface_ranker`)
- Scores each asset by technology stack, exposed sensitive ports, absence of WAF, prior findings, and high-value paths (`/admin`, `/api/`, `/.env`).
- **Output:** `surface_ranking.json` with `critical`/`high`/`medium`/`low` priority.

### 5.5 IDOR Tester / SSRF Hunter / SQLi Hunter / XSS Hunter / Bypass 403
All are **read-only** skills that do not mutate target data:
- Compare a baseline response against a safe probe and record the differential.
- Record `severity`, `evidence`, and `recommendation` for every candidate.
- Forward candidates to `validation_gate` before reporting.

### 5.6 Secrets Hunter / Cloud Recon / Param Discover
- **Secrets Hunter:** Matches key regexes (AWS, GitHub, Stripe, Slack, JWT, Private Key) or runs `trufflehog`/`gitleaks` when installed.
- **Cloud Recon:** Probes common S3/Azure/GCS bucket names derived from the target and logs open buckets.
- **Param Discover:** Uses `arjun`/`paramspider` when installed, falling back to Wayback Machine CDX.

### 5.7 Token Scan / Web3 Audit
- **Token Scan:** Scores token risk from unlimited minting, excessive fees, owner privileges, and inability to renounce ownership.
- **Web3 Audit:** Flags reentrancy, `tx.origin`, missing access control, `delegatecall`, and integer overflow patterns.

---

## 6. Dynamic Skill Registry

`skills/agent_core/skill_registry/` auto-discovers all skills from `skill.yaml` manifests:

```python
from skills.agent_core.skill_registry import SKILL_REGISTRY

# List all skills
summary = SKILL_REGISTRY.summary()
print(summary["total"], summary["by_category"])

# Execute a skill by name
result = await SKILL_REGISTRY.run("attack_surface_ranker", ctx)

# Fetch a skill instance
skill = SKILL_REGISTRY.get("idor_tester")
```

Recursive discovery uses `rglob("skill.yaml")` across all categories.

---

## 7. Autonomous Loop

`agent_autonomous_loop` runs a complete hunt cycle without manual intervention:

```
recon (surface ranker)
  → scan (tool planner)
  → analyze (idor/ssrf/sqlxss/secrets/takeover)
  → exploit (chain builder A→B→C)
  → validate (7-Question Gate: hunter_ai.validation_gate)
  → report (report_generator)
  → remember (log to hunt memory)
```

**Inputs:** `target`, `phases` (list of phases), `max_risk`, `scope_authorized`.
**Output:** `autonomous_hunt.json` containing the full execution trace (`trace`) and verified findings (`proven_findings`).

---

## 8. Hunt Memory (`/remember` and `/memory-gc`)

`agent_hunt_memory` handles memory actions:
- **remember:** `action="remember"`, `note="..."` → appends a JSONL line to `memory/<target>.jsonl`.
- **gc:** `action="gc"` → rotates files and retains the latest file per target.
- **list:** `action="list"` → lists memory files.

```python
await SKILL_REGISTRY.run("hunt_memory", Ctx(action="remember", note="id=5 suspect on /order", target="example.com"))
```

---

## 9. LLM Brain

`agent_llm_brain` assists decision-making:
- If `llm` is available in `ctx.extra["llm"]`, sends a prompt and parses the JSON response.
- Otherwise, uses offline-safe **heuristics**.
- **Output:** `llm_decision.json` containing `tool`, `skill`, `reasoning`, `confidence`, `next_skills`, and `source`.

---

## 10. Recommended End-to-End Workflow

```text
target.com
   │
   ▼
subdomain_enum → live_host_detection → httpx → tech_detection
   └───────────────────────────────────────┘
                      │
                      ▼
           attack_surface_ranker  (ranks highest-priority assets)
                      │
                      ▼
           agent_tool_planner  (selects next tool + fallback)
                      │
        ┌─────────────┼─────────────┐
        ▼             ▼             ▼
   idor_tester   ssrf_hunter   sqli_hunter
   xss_hunter    bypass_403    secrets_hunter
   takeover_confirm   logic_flaw_hunter
        │             │             │
        └─────────────┴─────────────┘
                      │
                      ▼
           agent_chain_builder  (A→B→C chains)
                      │
                      ▼
           agent_reasoning_loop  (evaluates next step + trace)
                      │
                      ▼
           validation_gate  (7-Question Gate — PROVEN only)
                      │
                      ▼
           report_generator  (submission-ready report)
                      │
                      ▼
           hunt_memory (remember)
```

---

## 11. Quick Code Examples

```python
import asyncio, json
from pathlib import Path
from skills.base_skill import SkillContext
from skills.agent_core.skill_registry import SKILL_REGISTRY

class FakeTM:
    def is_available(self, c): return c in ("subfinder","httpx","katana","arjun")

class FakeWS:
    def get_workspace_path(self, t, s): return Path(f"/tmp/ws/{t}/{s}")
    def write_file(self, *a, **k):
        p = Path("/tmp") / k.get("filename","out"); p.write_text(k["content"], encoding="utf-8"); return p
    def append_log(self, *a, **k): pass

class Ctx:
    def __init__(self, **kw):
        self.target="example.com"; self.session_id="s1"; self.retry_attempt=0
        self.tool_manager=FakeTM(); self.workspace=FakeWS(); self.extra=kw

async def main():
    ctx = Ctx(phase="recon", max_risk="medium", scope_authorized=True)

    # 1. Rank attack surface
    r = await SKILL_REGISTRY.run("attack_surface_ranker", ctx)
    ranking = json.loads(r.raw_output["ranking"])
    top = ranking["ranking"][0]["asset"]
    print("Top asset:", top)

    # 2. Plan tool
    p = await SKILL_REGISTRY.run("agent_tool_planner", ctx)
    plan = json.loads(p.raw_output["tool_plan"])
    print("Next tool:", plan["next_tool"]["tool"])

    # 3. Reasoning loop
    think = await SKILL_REGISTRY.run("agent_reasoning_loop",
        Ctx(phase="analyze", findings_so_far=[{"type":"idor","evidence":"id=5"}], goal="find idor"))
    action = json.loads(think.raw_output["next_action"])
    print("Next skill:", action["skill"], "| confidence:", action["confidence"])

    # 4. IDOR test
    idor = await SKILL_REGISTRY.run("idor_tester",
        Ctx(urls=["https://example.com/order?id=123"]))
    print("IDOR candidates:", len(json.loads(idor.raw_output["candidates"])))

    # 5. Exploit chain
    cb = await SKILL_REGISTRY.run("agent_chain_builder",
        Ctx(findings=[{"type":"subdomain_takeover","title":"dangling CNAME"}]))
    print("Chains:", len(json.loads(cb.raw_output["chains"])))

asyncio.run(main())
```

---

## 12. Adding a New Skill (Template)

Every new skill subclasses `BaseSkill`:

```python
from skills.base_skill import BaseSkill, SkillContext, SkillResult

class MyNewSkill(BaseSkill):
    name = "my_new_skill"
    category = "web"            # recon | scan | web | analysis | agent_core | reporting | web3
    description = "Short skill description"
    tools_required = ["nmap"]   # Primary tools
    fallback_tools = ["naabu"]  # Fallback tools
    timeout_seconds = 120.0
    max_retries = 2

    async def execute(self, ctx: SkillContext) -> SkillResult:
        result = SkillResult(skill_name=self.name, success=True, tool_used=self.name)
        # Implement logic using ctx.tool_manager and ctx.workspace
        result.add_finding(title="...", evidence="...", severity="Medium", ...)
        return result
```

Then:
1. Create `skills/<category>/<name>/` containing `skill.py`, `skill.yaml`, and `__init__.py`.
2. Export the skill in `skills/__init__.py` and `skills/<category>/__init__.py`.
3. `SkillRegistry` will discover it automatically from `skill.yaml`.

Example `skill.yaml`:
```yaml
name: my_new_skill
category: web
description: "Skill description"
version: "1.0"
input:
  - target: str
output:
  - result.json
depends_on: []
next_skills:
  - validation_gate
fallback_skills: []
tools_required: []
fallback_tools: []
timeout_seconds: 60
max_retries: 1
enabled: true
```

---

## 13. Core Rules (Always Active)

1. **Read full scope before touching any asset** — stay strictly inside authorized targets.
2. **No theoretical bugs** — ask "Can an attacker do this right now?" (7-Question Gate).
3. **Run the 7-Question Gate before writing any report** — submit `PROVEN` findings only.
4. **Kill weak findings fast** — N/A reports hurt signal and validity ratios.
5. **Impact first** — test worst-case consequences before low-value issues.
6. **Log every decision** — save `thinking_trace.json` for every reasoning cycle.
7. **5-minute rule** — if a tool yields nothing after 5 minutes, move on.

---

> Reference for adding skills or extending the agent: `AGENT_SKILLS_GUIDE.md` and skill source under `skills/`.
