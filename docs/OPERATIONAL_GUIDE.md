# HunterAI — Operational & Security Guide

This guide covers local deployment, authentication, scope governance, AI resource controls, evidence adjudication, and verification workflows for the unified HunterAI stack.

---

## 1. Prerequisites & Service Stack

### Local Requirements
- **Python 3.10+** (Django 5.2 ASGI control plane, `core/`, `hunter_ai/`, `agents/`)
- **Go 1.24+** (optional/recommended for `backend/` ARTEX-Pro concurrency engine)
- **Node.js 22+** (for `frontend/` Next.js Obsidian Sentinel UI)
- **PostgreSQL 15+** (for Go ARTEX-Pro persistence; SQLite is used for local `PlatformStore` and `core/vuln_intel`)
- **Playwright** (optional, for authenticated Browser Sensor runs)
- **Burp Suite** (optional, connects via local Burp Gateway on `127.0.0.1:8085`; default Burp Proxy stays on `127.0.0.1:8080`)

### Service Ports

| Component | Default Address | Configuration Variable |
| :--- | :--- | :--- |
| Next.js Obsidian Sentinel UI | `http://127.0.0.1:3000` | `FRONTEND_PORT` |
| Django ASGI Control Plane | `http://127.0.0.1:8000` | `WEB_PORT` |
| Go ARTEX-Pro REST API | `http://127.0.0.1:7071` | `ARTEX_BIND_ADDR` |
| PostgreSQL | `127.0.0.1:5432` | `POSTGRES_PASSWORD`, `ARTEX_DB_SSLMODE` |
| Burp Gateway REST Bridge | `http://127.0.0.1:8085` | `HUNTER_BURP_GATEWAY_ALLOW_REMOTE` |
| ModSecurity WAF Lab | `http://127.0.0.1:8088` | `docker-compose.waf-lab.yml` |

### Starting the Stack

```bash
# Install Python dependencies
pip install -r requirements.txt

# Launch full unified stack (PostgreSQL + Go :7071 + Django :8000 + Next.js :3000)
python pentest.py artex target.com

# Launch Web Control Center only (Django :8000 + Next.js :3000)
python pentest.py web

# Launch OpenCode Studio Hub (:3000/studio + Django :8000)
python pentest.py opencode

# Headless CLI engagement
python pentest.py all target.com

# Optional local WAF validation lab (bound to :8088 to avoid :8080 Burp Proxy conflict)
docker compose -f docker-compose.waf-lab.yml up -d
```

---

## 2. Control Plane Authentication & Fail-Closed Defaults

All control-plane boundaries default to **fail-closed**. See [docs/security.md](security.md) for the complete control matrix.

- **Django Bearer & Session Auth (`hunter_backend/auth.py`):** Protected `/api/*` endpoints return `401 Unauthorized` without credentials. Provide `HUNTER_API_TOKEN` or read the auto-generated `0o600` CSPRNG token at `data/root_controller/.api_token`. Only `/api/health`, `/api/csrf`, `/api/platform/artex/health`, and top-level UI redirects are unauthenticated.
- **Privilege Tiers:** Human operator credentials (`userTier`) are required for approval decisions (`/api/platform/approvals/<id>/decide`), `.env` settings saves (`/api/settings/save`), red-team grant issuance/revocation, run control (`pause`/`resume`/`stop`), and editor writes. Agent/read tokens (`tokenTier`) receive `403 Forbidden` on privileged mutations.
- **Session Revocation:** `POST /api/auth/revoke` increments the monotonic session generation counter (`sgn`), invalidating all previously issued cookies and `hnt1.*` bearer tokens immediately.
- **CSRF, Origin & WebSockets:** Cookie-authenticated mutations require both a trusted `Origin` and a valid double-submit `X-CSRFToken`. WebSocket connections without valid bearer credentials fail closed when `Origin` is missing or untrusted.
- **Go ARTEX-Pro (`backend/`):** Binds `127.0.0.1:7071` by default, requires `ARTEX_API_TOKEN` (or `HUNTER_API_TOKEN` / startup CSPRNG token) on `/api/v1/*` endpoints other than `/api/v1/health`, and rejects private/loopback/cloud-metadata scan targets unless `ARTEX_ALLOW_LOCAL_SCAN=1` is set for local labs (metadata IPs remain non-overridable).
- **Burp Gateway (`core/burp_gateway/gateway.py`):** Refuses non-loopback binds unless `HUNTER_BURP_GATEWAY_ALLOW_REMOTE=1` and requires constant-time token authentication via `X-Hunter-Token` or `Authorization: Bearer`.
- **Fail-Closed Execution Mode (`core/security_mode.py`):**
  - `unrestricted_mode()` returns `False` unless `HUNTER_UNRESTRICTED` is explicitly set to a truthy value (`1`/`true`/`yes`/`on`).
  - `web_governance_enforced()` returns `True` unless `HUNTER_WEB_UNRESTRICTED` is explicitly set to a truthy value.
  - Even when opted in, Evidence Court proof requirements, artifact secret scrubbing, cloud metadata/link-local SSRF blocks, dangerous scheme checks, shell metacharacter filtering, and CSRF/Origin guards remain active.

---

## 3. Scope Enforcement, Operational Modes & Approvals

### Network Scope Firewall (`core/network_scope_guard.py`, `core/scope_guard.py`)

Outbound probes pass through scope and SSRF validation before socket creation:
- Permits `http` and `https` schemes only.
- Enforces explicit domain/host/CIDR/URL-prefix allowlists and exclusion lists.
- Blocks cloud metadata endpoints (`169.254.169.254`, `100.100.100.200`, `fd00:ec2::254`, `metadata.google.internal`, `metadata.internal`), link-local addresses, unspecified addresses (`0.0.0.0`, `::`), and DNS-rebound internal targets.
- Inspects redirect targets before following.

Example `scope.yaml`:

```yaml
scope:
  allowed_targets:
    - "staging.example.com"
    - "*.api.example.com"
  excluded_targets:
    - "billing.example.com"
    - "10.0.0.0/8"
  excluded_paths:
    - "/logout"
    - "/delete-account"
    - "/reset-db"
  allow_private_ips_override: false
```

### Passive vs Active Modes (`core/execution_modes.py`)

- **`PASSIVE` (Default):** Endpoint discovery, sitemap/JS analysis, and header inspection without sending active exploitation probes.
- **`ACTIVE` (Explicit Opt-In):** Dispatches targeted differential verification probes only after explicit authorization:

```python
from core.execution_modes import ExecutionMode, ModeManager

modes = ModeManager()
modes.switch_mode(
    ExecutionMode.ACTIVE,
    reason="Authorized staging engagement",
    authorized_by="Lead Security Engineer",
)
```

### Signed Red-Team Grants & HITL Approval Integrity

- **Signed Grants (`core/policy/red_team.py`):** Bind engagement scope, validity window, and allowed profiles (`safe`, `standard`, `red_team`) into an HMAC-SHA256-signed `AuthorizationGrant` evaluated by `ToolRegistry._enforce_policy()`. Hard invariants (persistence/backdoors, C2, lateral movement, destructive writes, evasion, exfiltration, credential dumping) remain denied under every profile.
  ```bash
  python scripts/authorize_full_power.py issue --scope "staging.example.com" --authorized-by "Engagement SOW" --days 7
  python scripts/authorize_full_power.py check --target staging.example.com
  python scripts/authorize_full_power.py revoke
  ```
- **HITL Approval Queue (`core/platform_store.py`, `hunter_backend/apps/platform_api.py`):** Copilot never auto-executes markdown shell blocks; eligible proposals enter the approval queue with an immutable SHA-256 `proposal_digest` over canonical execution fields (`action_type`, `tool_name`, `target`, `raw_command_args`, `engagement_id`, `scope`). Redacted display fields are stored separately from execution arguments, and tampered digests return `403`.

---

## 4. LLM Routing, Context Compaction & VRAM Management

- **Provider Policy (`HUNTER_LLM_POLICY` in `core/llm_router.py`):**
  - `cloud_first` (default): uses configured cloud API keys (`OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, `GEMINI_API_KEY`, `DEEPSEEK_API_KEY`, `GROQ_API_KEY`, `OPENROUTER_API_KEY`), falling back to local Ollama.
  - `local_first`: prefers local Ollama, falling back to cloud APIs.
  - `local_only`: local Ollama only (use when engagement rules forbid external LLM egress).
  - `cloud_only`: cloud providers only.
- **Context & Prompt-Injection Hygiene (`core/context/`):** Automatically compacts long histories (`compact_chain`, `microcompact_messages`), offloads oversized tool responses (`maybe_offload_tool_result`), and wraps untrusted external content (`wrap_untrusted_tool_output`).
- **Single-Model VRAM Discipline (`core/llm/gpu_scheduler.py`):** `GPUScheduler` serializes local model leases with priority preemption (interactive Copilot requests preempt background scan tasks) and configurable `HUNTER_OLLAMA_KEEP_ALIVE_SEC` plus pressure-based eviction.

---

## 5. Evidence Court (7-State Verdicts) & False-Positive Refutation

`core/evidence_court.py` adjudicates findings into seven canonical states: `UNVERIFIED`, `CANDIDATE`, `CONFIRMED`, `REJECTED`, `INCONCLUSIVE`, `UNAVAILABLE`, and `ERROR`.

| Raw Signal | Naive Scanner Behavior | Evidence Court Handling | Canonical Verdict |
| :--- | :--- | :--- | :--- |
| HTTP 500 on single quote (`'`) | Reports SQLi | Checks for syntax/boolean differential vs unhandled error | `REJECTED` |
| Input echoed inside HTML | Reports XSS | Tests unencoded tag/attribute breakout against an encoding control | `REJECTED` |
| WAF `403 Forbidden` block | Reports anomaly/bypass | Identifies WAF interception; does not attribute origin execution | `REJECTED` |
| High-entropy token in JS | Reports leaked key | Requires provider token format plus Shannon entropy validation | `REJECTED` / `UNVERIFIED` |
| Missing binary / unreachable host | Reports negative or crashes | Records tool/transport unavailability explicitly | `UNAVAILABLE` |

### Confirmed Finding Contract

Confirmed findings include structured verification metadata and reproducible proof steps:

```json
{
  "id": "FND-A1B2C3D4",
  "vulnerability_type": "xss",
  "title": "Reflected Cross-Site Scripting (XSS) in 'q'",
  "severity": "HIGH",
  "confidence": 0.98,
  "target": "staging.example.com",
  "endpoint": "/search",
  "parameter": "q",
  "evidence": "Input reflected unencoded with tag breakout: \"><hunter_xss_4210>",
  "verification": {
    "verdict": "CONFIRMED",
    "verifier_name": "EvidenceCourt",
    "methodology": "Deterministic Nonce Context Breakout",
    "proof_token": "hunter_xss_4210"
  },
  "reproducibility": {
    "is_reproducible": true,
    "reproduction_curl": "curl -i -s 'https://staging.example.com/search?q=%22%3E%3Chunter_xss_4210%3E'"
  },
  "cwe": "CWE-79",
  "owasp": "A03:2021-Injection"
}
```

---

## 6. Isolated Blue-Team Detection Library (`detections/`)

Defenders auditing a host or SIEM for ARTEX activity can use the isolated static pack under `detections/` without invoking offensive tooling:

- Convert Sigma rules (`detections/sigma/`) with `sigma check` / `sigma convert` (see [detections/README.md](../detections/README.md) for backend portability).
- Load Suricata signatures from `detections/suricata/` or import indicators from `detections/indicators/artex_indicators.{csv,misp.json}`.
- Run read-only host triage via `python detections/triage/artex_host_triage.py --self-test`.

---

## 7. Pre-Engagement Verification Checklist

Run these checks before starting an assessment:

```bash
# Environment readiness (local tools, Ollama, Burp, Playwright, wordlists)
python -m core.readiness --timeout 5

# Skill registry & tool catalog parity
python tools/install_opencode_skills.py --check
python scripts/sync_tool_manifests.py --check

# External isolation & security hardening regression suites
python -m pytest tests/test_external_isolation.py tests/security/ -q

# Causal validation arena & 16-gate certification pipeline
python run_causal_validation_arena.py
python certify.py

# Safe read-only detector demo (loopback target)
python -m core.detectors.cli demo
```

---

## 8. Legal & Authorization Notice

HunterAI is intended exclusively for authorized penetration testing, bug bounty engagements with explicit safe-harbor terms, and defensive security engineering. Probing systems without prior written authorization is prohibited.
