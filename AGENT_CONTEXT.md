# AGENT_CONTEXT: HunterAI Autonomous Computer-Security Agent

> **Master System Architecture, Operating Principles, and Knowledge Base for AI Editors and Autonomous Agents**

---

## 1. PROJECT & MISSION
**HunterAI** is an autonomous, air-gapped **Computer Security Agent** and **Attack Surface Management Platform** designed for Kali Linux and authorized enterprise environments.

### The Non-Rejection Principle within Scope
```text
You are HunterAI, an autonomous security research and testing orchestrator
operating inside an explicitly authorized assessment scope.

Your job is to investigate the authorized target, operate available tools,
browser automation, Burp, filesystem, and local AI models, collect evidence,
form hypotheses, verify them safely, and produce reproducible findings.

Security-related tasks are NOT inherently prohibited.
Evaluate every action against the active authorization scope and policy.
Never claim verification without reproducible differential evidence.
```

---

## 2. HIGH-LEVEL CONTROL PLANE ARCHITECTURE

```text
                               ┌─────────────────────────────────┐
                               │       HUNTERAI ORCHESTRATOR     │
                               │        Autonomous Control       │
                               └────────────────┬────────────────┘
                                                │
                 ┌──────────────────────────────┼──────────────────────────────┐
                 ▼                              ▼                              ▼
        ┌──────────────────┐          ┌───────────────────┐          ┌───────────────────┐
        │  COMPUTER CTRL   │          │  BROWSER WORKER   │          │   BURP BRIDGE     │
        │  (Terminal & OS) │          │  (Playwright Eng) │          │  (traffic.db)     │
        └────────┬─────────┘          └─────────┬─────────┘          └─────────┬─────────┘
                 │                              │                              │
                 └──────────────────────────────┼──────────────────────────────┘
                                                ▼
                                    ┌───────────────────────┐
                                    │      POLICY GATE      │
                                    │ (Non-Bypassable Rule) │
                                    └───────────┬───────────┘
                                                │
                                    ┌───────────▼───────────┐
                                    │    ACTION LOOP        │
                                    │   (Observe -> Act)    │
                                    └───────────┬───────────┘
                                                │
                 ┌──────────────────────────────┼──────────────────────────────┐
                 ▼                              ▼                              ▼
        ┌──────────────────┐          ┌───────────────────┐          ┌───────────────────┐
        │  LOCAL TRIAD     │          │  EVIDENCE GRAPH   │          │  DECISION CORE    │
        │  (Ollama AI)     │          │  (Verified Tree)  │          │  (Signal Tracks)  │
        └──────────────────┘          └───────────────────┘          └───────────────────┘
```

---

## 3. AVAILABLE LOCAL AI MODELS (THE MODEL COUNCIL)

All inference runs **100% locally** via Ollama (Air-Gapped, Zero External Data Leakage):
1. **`qwen2.5-coder:14b` — The Code Architect & Parser**:
   - Analyzes JavaScript AST, source code, undocumented parameters, APIs.
   - Operates the **Context Compressor** to digest hundreds of crawled assets into standardized knowledge schemas.
2. **`xploiter/pentester:latest` — The Fast Recon & Triage Scout**:
   - Performs rapid triage on mass tool outputs, filters out dead hosts, removes noise.
3. **`WhiteRabbitNeo / Llama-3.1-WhiteRabbitNeo-2-8B:latest` — The Security Reasoning Specialist**:
   - Explores business logic, authorization boundaries, IDOR, SSRF, injection hypotheses.
   - Formulates structured verification plans for the deterministic engine.

---

## 4. BROWSER WORKER & PLAYWRIGHT CAPABILITIES

The autonomous browser worker (`core/browser/playwright_controller.py`) is an independent Playwright automation engine:
- **Headless & Headed Execution**: Chromium or Firefox.
- **Burp Suite Proxy Upstream**: Default proxy `http://127.0.0.1:8080` routes all Playwright traffic into Burp Suite.
- **Evidence Output Schema**:
  ```text
  browser/
  ├── pages.json             # Discovered URLs and titles
  ├── screenshots/           # DOM and element full-page captures
  ├── requests.jsonl         # All HTTP requests intercepted
  ├── responses.jsonl        # All HTTP response headers & status
  ├── cookies.json           # Active cookies per session
  ├── storage.json           # localStorage & sessionStorage dumps
  ├── console.log            # Client-side JavaScript console errors
  └── traces/                # Playwright execution trace zip files
  ```
- **DOM Form Extraction**: Automatically parses HTML forms, CSRF tokens, input fields, and action endpoints.

---

## 5. TRAFFIC BRIDGE & BURP INTEGRATION (`traffic.db`)

Every HTTP request generated by Playwright or proxied through Burp Suite is intercepted by `TrafficBridge` (`core/browser/traffic_bridge.py`):
1. Stored in SQLite (`data/traffic.db`).
2. Scanned in real-time for **New Endpoints** (`/api/...`).
3. Automatically creates `EndpointNode` and `ParameterNode` in the `EvidenceGraph`.

---

## 6. MULTI-ROLE AUTHENTICATION CONTEXT (`auth_context/`)

Separates authentication personas to verify Broken Access Control without guessing:
- `anonymous.json`: Unauthenticated baseline.
- `user_a.json`: Primary tenant / User A session & tokens.
- `user_b.json`: Secondary tenant / User B session & tokens.
- `admin.json`: Administrative privileges (when authorized).
- `expired.json`: Revoked session to check session invalidation.

---

## 7. SCOPE GOVERNANCE & IMMUTABLE POLICY GATE

The LLM **CANNOT** modify the policy rules:
```text
LLM -> REQUEST ACTION -> POLICY GATE -> ALLOW / DENY -> EXECUTOR
```
- **Inviolable Invariants (Never Overridable)**:
  - Loopback (`127.0.0.0/8`, `::1`, `localhost`) strictly blocked.
  - Cloud Metadata (`169.254.169.254`, `metadata.google.internal`) strictly blocked.
  - Destructive commands (`rm -rf /`, `mkfs`, fork bombs) strictly blocked.
- **Lab Mode (`--lab-mode`)**:
  - Permits private RFC1918 subnets (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`) for authorized labs. Cloud metadata remains blocked.

---

## 8. EVIDENCE RULES & THE DETERMINISTIC VALIDATOR

The core operational creed of HunterAI:
```text
OBSERVATION != FACT
FACT != HYPOTHESIS
HYPOTHESIS != VULNERABILITY
CONFIDENCE != VERIFICATION
```
- A confidence score of $0.95$ without reproducible differential evidence is marked as `status: candidate` (never `verified`).
- Findings require:
  1. Cryptographic request/response hashes.
  2. Arithmetic nonce proof (e.g. `$((41+1)) -> 42`) or differential status transition (e.g. 403 vs 200).
  3. Minimum confidence score $\ge 0.85$.

---

## 9. FAILURE MEMORY & ANTI-LOOP POLICY

Stored in `data/failure_memory.json`:
- **Policy**: `do_not_repeat_without_new_evidence`.
- If a tool or fuzzing run fails on an endpoint, the agent will never re-run the same action unless new differential evidence has emerged.
- Rejected hypotheses are permanently logged to prevent LLM reasoning cycles from re-testing debunked theories.

---

## 10. DYNAMIC DECISION TRACKS

Signals trigger specialized test tracks automatically:
- **WordPress**: `wpscan`, `/wp-json/` REST API user enumeration.
- **GraphQL**: `/graphql` schema introspection query test.
- **OpenAPI / Swagger**: `/swagger.json` endpoint schema parsing.
- **File Upload**: Multipart form inspection, benign canary upload.
- **JWT / Auth**: Alg=none, key confusion, token expiration.
- **SSRF / Redirect**: `redirect=`, `url=`, `dest=` parameter validation.

---

## 11. STANDARDIZED STAGE ARTIFACTS & MANIFESTS

Every stage outputs:
1. `stage.raw.txt`: Raw tool output.
2. `stage.parsed.json`: Normalized JSON schema.
3. `stage.lineage.json`: Execution metadata, timing, sha256 hashes.
4. `manifest.json`: Stage lifecycle manifest tracking inputs, outputs, artifacts, parent nodes, child nodes, and status.
